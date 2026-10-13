/// Адрес из `dwRemoteAddr`: байты в памяти идут в сетевом порядке.
pub fn ipv4_from_dword(addr: u32) -> String {
    let bytes = addr.to_ne_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Порт из `dwRemotePort`: младшие 16 бит в сетевом порядке.
pub fn tcp_port(port: u32) -> u16 {
    u16::from_be(port as u16)
}

/// `CLOSED` и `LISTEN` не являются исходящей попыткой.
pub fn interesting_tcp_state(state: u32) -> bool {
    !matches!(state, 1 | 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_windows_ipv4_and_port() {
        assert_eq!(ipv4_from_dword(0x140A_0A0A), "10.10.10.20");
        assert_eq!(tcp_port(0x1600), 22);
        assert_eq!(tcp_port(0xAE08), 2222);
        assert!(!interesting_tcp_state(2));
        assert!(interesting_tcp_state(5));
    }
}
