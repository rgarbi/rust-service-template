FROM rust:latest AS builder

RUN update-ca-certificates

# Create appuser
ENV USER=rust-service-template
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"


WORKDIR /rust-service-template

COPY ./ .

ENV SQLX_OFFLINE true
RUN cargo build --release

######################
FROM ubuntu:latest as rust-service-template

RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /rust-service-template

# Copy our build
COPY --from=builder /rust-service-template/target/release/rust-service-template ./
COPY --from=builder /rust-service-template/configuration ./configuration

# Use an unprivileged user.
USER rust-service-template:rust-service-template

EXPOSE 8000
ENV APP_ENVIRONMENT production

CMD ["/rust-service-template/rust-service-template"]
