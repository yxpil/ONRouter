//! 响应体 gzip 压缩流（对标 nginx ngx_http_gzip_module 的输出阶段）。

use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use flate2::write::GzEncoder;
use http_body::{Body, SizeHint};
use hyper::body::Frame;

use crate::server::RespBody;

/// 解析请求的 `Accept-Encoding`：是否接受 gzip。
/// 尊重 `q=0` 排除；`*` 视为接受 gzip。
pub fn accepts_gzip(header: &str) -> bool {
    for tok in header.split(',') {
        let mut parts = tok.trim().split(';');
        let name = parts.next().unwrap_or("").trim();
        if !(name.eq_ignore_ascii_case("gzip") || name == "*") {
            continue;
        }
        let mut q = 1.0f32;
        for p in parts {
            if let Some((k, v)) = p.trim().split_once('=') {
                if k.trim().eq_ignore_ascii_case("q") {
                    q = v.trim().parse::<f32>().unwrap_or(1.0);
                }
            }
        }
        if q > 0.0 {
            return true;
        }
    }
    false
}

/// 把内层未压缩响应体逐帧压缩为 gzip 流。
///
/// 采用 `GzEncoder<Vec<u8>>`：每帧 `write_all`+`flush` 后把累加的压缩字节 `take`
/// 出来作为一帧下发；内层耗尽时 `try_finish` 追加 gzip 尾（CRC32 + ISIZE）。
/// Vec 作为 sink 的写入不可能失败，故压缩路径自身不产生 `hyper::Error`——
/// 只有内层体的错误会原样透传（`hyper::Error` 无公开构造器，无法新建）。
pub struct GzipBody {
    inner: RespBody,
    enc: GzEncoder<Vec<u8>>,
    /// 内层已耗尽且 `try_finish` 完成：后续轮询直接产出 `None`
    finished: bool,
}

impl GzipBody {
    pub fn new(inner: RespBody, level: u32) -> Self {
        GzipBody {
            inner,
            enc: GzEncoder::new(Vec::new(), flate2::Compression::new(level)),
            finished: false,
        }
    }
}

impl Body for GzipBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        // SAFETY: 我们从不把 inner/enc 移出 GzipBody，只把它们借成 Pin<&mut _>，
        // 不违反 pin 契约（与 LoggedBody 同样的自持字段模式）。
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        loop {
            if this.finished {
                return Poll::Ready(None);
            }
            let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
            match inner.poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        // Vec sink：write_all/flush 不可能 Err，忽略 Result。
                        let _ = this.enc.write_all(data);
                        let _ = this.enc.flush();
                        let out = std::mem::take(this.enc.get_mut());
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                        }
                        // 该帧尚未产出压缩字节：继续轮询内层（不能返回 Pending，无唤醒登记）。
                    }
                    // 纯 trailer 帧：忽略，继续。
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    let _ = this.enc.try_finish();
                    let out = std::mem::take(this.enc.get_mut());
                    this.finished = true;
                    if out.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        // 压缩后的字节数不可预知：返回未知长度（lower=0, upper=None）。
        SizeHint::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use http_body_util::BodyExt;
    use std::collections::VecDeque;
    use std::io::Read;

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut dec = GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    /// 测试用：把一组 Bytes 逐帧下发的响应体（Error 与 RespBody 一致 = hyper::Error）。
    struct Chunks(VecDeque<Bytes>);

    impl Body for Chunks {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            match self.0.pop_front() {
                Some(b) => Poll::Ready(Some(Ok(Frame::data(b)))),
                None => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn parses_accept_encoding() {
        assert!(accepts_gzip("gzip"));
        assert!(accepts_gzip("gzip, deflate, br"));
        assert!(accepts_gzip("deflate, gzip;q=1.0"));
        assert!(accepts_gzip("gzip;q=0.5"));
        assert!(accepts_gzip("*"));
        assert!(accepts_gzip("br, *;q=0.3"));
        assert!(!accepts_gzip("gzip;q=0"));
        assert!(!accepts_gzip("identity;q=0, *;q=0"));
        assert!(!accepts_gzip("br"));
        assert!(!accepts_gzip(""));
    }

    #[tokio::test]
    async fn single_frame_round_trips() {
        let text = "Hello, ONRouter! ".repeat(500);
        let inner = crate::server::full_body(Bytes::from(text.clone()));
        let collected = GzipBody::new(inner, 6).collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..2], &[0x1f, 0x8b], "gzip 魔数");
        assert_eq!(gunzip(&collected), text.as_bytes());
        assert!(collected.len() < text.len(), "可压缩文本应显著变小");
    }

    #[tokio::test]
    async fn multi_frame_round_trips() {
        let chunks = vec![
            Bytes::from("chunk-one "),
            Bytes::from("chunk-two "),
            Bytes::from("chunk-three"),
        ];
        let inner: RespBody = Chunks(VecDeque::from(chunks)).boxed();
        let collected = GzipBody::new(inner, 1).collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..2], &[0x1f, 0x8b]);
        assert_eq!(
            String::from_utf8(gunzip(&collected)).unwrap(),
            "chunk-one chunk-two chunk-three"
        );
    }

    #[tokio::test]
    async fn empty_body_is_valid_gzip() {
        // 空响应体也必须产出合法 gzip 流（能解出空内容）：验证 try_finish 尾字节路径。
        let inner = crate::server::full_body(Bytes::new());
        let collected = GzipBody::new(inner, 6).collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..2], &[0x1f, 0x8b]);
        assert!(gunzip(&collected).is_empty());
    }
}
