lint:
	cargo clippy --all-targets --all -- --deny=warnings

fmt:
	cargo fmt

build-web:
	rm -rf dist \
	&& cd web \
	&& yarn install --network-timeout 600000 && yarn build \
	&& cp -rf dist ../

bench:
	cargo bench

dev:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c=conf/pingap.toml'

devtest:
	RUST_LOG=DEBUG cargo watch -w src -x 'run -- -c=/Users/urtur/.yandex.disk/80473/Yandex.Disk.localized/waf/pingap/conf/pingap.toml --admin=127.0.0.1:3018'

devetcd:
	RUST_LOG=INFO cargo watch -w src -x 'run -- -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&user=pingap&password=123123" --admin=127.0.0.1:3018'


udeps:
	cargo +nightly udeps

msrv:
	cargo msrv verify


bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

test:
	cargo test

cov:
	cargo llvm-cov --html --open

release:
	cargo build --release
	ls -lh target/release

perf:
	cargo build --profile=release-perf --features=perf
	ls -lh target/release-perf
pyro:
	cargo build --profile=release-perf --features=pyro
	ls -lh target/release-perf

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/
