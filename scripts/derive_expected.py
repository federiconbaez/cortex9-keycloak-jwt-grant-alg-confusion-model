#!/usr/bin/env python3
print("id\tkind\tpre\tpost")
for row in [
    ("p01_hs256_on_pubkey_idp","pos","ACCEPT","REJECT"),
    ("p02_hs512_on_pubkey_idp","pos","ACCEPT","REJECT"),
    ("p03_none_alg","pos","ACCEPT","REJECT"),
    ("n01_rs256","neg","ACCEPT","ACCEPT"),
    ("n02_es256","neg","ACCEPT","ACCEPT"),
    ("n03_expected_mismatch","neg","REJECT","REJECT"),
    ("n04_null_alg","neg","REJECT","REJECT"),
    ("n05_hs256_with_expected_rs","neg","REJECT","REJECT"),
]:
    print("\t".join(row))
