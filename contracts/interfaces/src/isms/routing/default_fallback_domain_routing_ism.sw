library;

abi DefaultFallbackDomainRoutingIsm {
    #[storage(write, read)]
    fn initialize(owner: b256, mailbox: b256);

    #[storage(write, read)]
    fn initialize_with_domains(
        owner: b256,
        mailbox: b256,
        domains: Vec<u32>,
        modules: Vec<b256>,
    );

    #[storage(write, read)]
    fn set(domain: u32, module: b256);

    #[storage(write, read)]
    fn remove(domain: u32);

    #[storage(read)]
    fn domains() -> Vec<u32>;

    #[storage(read)]
    fn module(domain: u32) -> b256;
}
