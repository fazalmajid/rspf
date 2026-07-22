use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use super::request::{PolicyRequest, RequestParseError};
use super::response::Action;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error(transparent)]
    Parse(#[from] RequestParseError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Frames a byte stream on Postfix's policy-request terminator: a blank line
/// (i.e. two consecutive `\n`s) ends one request, which may itself be followed
/// immediately by further pipelined requests on the same connection.
#[derive(Debug, Default)]
pub struct PolicyRequestCodec;

impl Decoder for PolicyRequestCodec {
    type Item = PolicyRequest;
    type Error = ProtoError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(terminator_at) = find_double_newline(src) else {
            return Ok(None);
        };

        let block = src.split_to(terminator_at);
        // Drop the "\n\n" terminator itself.
        src.advance(2);

        let lines: Vec<String> = block
            .as_ref()
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect();

        Ok(Some(PolicyRequest::from_lines(&lines)?))
    }
}

/// Returns the byte offset of the first `\n\n` in `buf`, if any.
fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n")
}

impl Encoder<Action> for PolicyRequestCodec {
    type Error = ProtoError;

    fn encode(&mut self, item: Action, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let wire = item.to_wire();
        dst.reserve(wire.len());
        dst.put_slice(wire.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> Vec<PolicyRequest> {
        let mut codec = PolicyRequestCodec;
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for chunk in chunks {
            buf.extend_from_slice(chunk);
            while let Some(req) = codec.decode(&mut buf).unwrap() {
                out.push(req);
            }
        }
        out
    }

    #[test]
    fn decodes_single_request() {
        let raw = b"request=smtpd_access_policy\nclient_address=192.0.2.10\n\n";
        let reqs = decode_all(&[raw]);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].client_address.as_deref(), Some("192.0.2.10"));
    }

    #[test]
    fn buffers_partial_reads_across_multiple_chunks() {
        let reqs = decode_all(&[
            b"request=smtpd_access",
            b"_policy\nclient_addr",
            b"ess=192.0.2.10\n",
            b"\n",
        ]);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].request.as_deref(), Some("smtpd_access_policy"));
        assert_eq!(reqs[0].client_address.as_deref(), Some("192.0.2.10"));
    }

    #[test]
    fn decodes_pipelined_requests_in_one_buffer() {
        let raw = b"client_address=192.0.2.10\n\nclient_address=192.0.2.20\n\n";
        let reqs = decode_all(&[raw]);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].client_address.as_deref(), Some("192.0.2.10"));
        assert_eq!(reqs[1].client_address.as_deref(), Some("192.0.2.20"));
    }

    #[test]
    fn incomplete_request_yields_none() {
        let mut codec = PolicyRequestCodec;
        let mut buf = BytesMut::from(&b"client_address=192.0.2.10\n"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn malformed_line_is_a_decode_error() {
        let mut codec = PolicyRequestCodec;
        let mut buf = BytesMut::from(&b"not_a_kv_pair\n\n"[..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encodes_action_with_terminator() {
        let mut codec = PolicyRequestCodec;
        let mut buf = BytesMut::new();
        codec.encode(Action::Dunno, &mut buf).unwrap();
        assert_eq!(&buf[..], b"action=dunno\n\n");
    }
}
