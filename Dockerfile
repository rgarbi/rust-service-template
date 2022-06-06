FROM rust:latest AS builder

RUN update-ca-certificates

# Create appuser
ENV USER={{ tmplr.project_name }}
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"


WORKDIR /{{ tmplr.project_name }}

COPY ./ .

ENV SQLX_OFFLINE true
RUN cargo build --release

######################
FROM ubuntu:latest as {{ tmplr.project_name }}

RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /{{ tmplr.project_name }}

# Copy our build
COPY --from=builder /{{ tmplr.project_name }}/target/release/{{ tmplr.project_name }} ./
COPY --from=builder /{{ tmplr.project_name }}/configuration ./configuration

# Use an unprivileged user.
USER {{ tmplr.project_name }}:{{ tmplr.project_name }}

EXPOSE 8000
ENV APP_ENVIRONMENT production

CMD ["/{{ tmplr.project_name }}/{{ tmplr.project_name }}"]
