use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)] // اضافه کردن PartialEq, Eq برای مقایسه
pub enum PacketKind {
    Syn,
    Data,
    Fin,
    SynAck,
    Heartbeat,
    HeartbeatAck,
}

#[derive(Debug, Clone)]
pub struct SuitPacket {
    pub kind: PacketKind,
    pub tunnel_id: u32,
    pub seq: u32,
    pub payload: Bytes,
}
