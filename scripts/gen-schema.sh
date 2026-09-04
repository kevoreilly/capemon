#!/usr/bin/env bash
# Regenerate schema.pb.{c,h} from schema.proto + schema.options.
#
# schema.proto is the capemon copy of CAPEv2's data/capemon_pb.proto - keep the
# two byte-identical except for this header comment. After editing either, run
# this script here AND regenerate the CAPEv2 Python parser:
#
#   (in CAPEv2)  protoc -I=data --python_out=lib/cuckoo/common/ data/capemon_pb.proto
#
# Requires the nanopb 0.4.9.x generator (matches the vendored nanopb/ runtime,
# PB_PROTO_HEADER_VERSION 40) and a protoc. Both come from pip:
#
#   python -m pip install "nanopb==0.4.9.1" grpcio-tools
#
set -euo pipefail
cd "$(dirname "$0")/.."

python -m nanopb.generator.nanopb_generator \
  -I . \
  -f schema.options \
  -D . \
  -L '#include "nanopb/%s"' \
  --no-timestamp \
  schema.proto

echo "wrote schema.pb.h / schema.pb.c"
