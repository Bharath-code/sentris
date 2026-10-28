use clap::Parser;
use sentris::cli::{handlers, Cli};

fn main() {
    let cli = Cli::parse();
    handlers::execute(cli);
}
