FROM rust:1.87-bookworm

# Test dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Layer 1: cache dependencies (only re-run when Cargo.toml/lock changes)
COPY Cargo.toml Cargo.lock* ./
COPY crates/unsee-core/Cargo.toml crates/unsee-core/Cargo.toml
COPY crates/unsee-redact/Cargo.toml crates/unsee-redact/Cargo.toml
COPY crates/unsee-pty/Cargo.toml crates/unsee-pty/Cargo.toml
COPY crates/unsee-guard/Cargo.toml crates/unsee-guard/Cargo.toml
COPY crates/unsee-cli/Cargo.toml crates/unsee-cli/Cargo.toml

# Create stub files so cargo can resolve the workspace
RUN mkdir -p crates/unsee-core/src && echo "" > crates/unsee-core/src/lib.rs \
    && mkdir -p crates/unsee-redact/src && echo "" > crates/unsee-redact/src/lib.rs \
    && mkdir -p crates/unsee-pty/src && echo "" > crates/unsee-pty/src/lib.rs \
    && mkdir -p crates/unsee-guard/src && echo "" > crates/unsee-guard/src/lib.rs \
    && mkdir -p crates/unsee-cli/src && echo "fn main() {}" > crates/unsee-cli/src/main.rs

# Pre-fetch and compile dependencies
RUN cargo build --workspace 2>/dev/null || true
RUN rm -rf crates/

# Layer 2: copy real source and build
COPY . .
RUN touch crates/*/src/*.rs crates/*/src/**/*.rs 2>/dev/null || true

CMD ["cargo", "test", "--workspace"]
