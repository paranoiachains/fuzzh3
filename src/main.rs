fn main() -> anyhow::Result<()> {
    env_logger::init();
    fuzzh3::run()
}
