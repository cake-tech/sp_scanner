// Correctness gate for the v2 binary block decoder (ScanSession.scanBlock)
// against the real fixture captured from electrs-tweaks's regtest build —
// see sp-scan-bench/docs/adr/0014-correctness-gate-covers-binary-decoder.md
// (this fixture must come from a real server, not a harness-synthesized
// one) and electrs-tweaks's doc/tweaks_v2_fixture.md (the capture itself,
// including the genuine BIP-352 payment built with sp-scan-bench/paygen and
// the exact receiver keys used to produce it).
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sp_scanner/sp_scanner.dart';

void main() {
  // Receiver keys from doc/tweaks_v2_fixture.md — throwaway keys generated
  // for that capture, not any real wallet's keys.
  final bScanHex = '22' * 32;
  final bSpendCompressedHex =
      '023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1';
  final receiver = Receiver(bScanHex, bSpendCompressedHex, false, const [], 0);

  // The same block (height 112), captured twice from the same server: once
  // as v1 JSON, once as the v2 binary blob. Both describe the identical
  // underlying TweakTxRow — see doc/tweaks_v2_fixture.md for the full
  // capture and the worked txid byte-order example.
  const v1TxidDisplayHex =
      '38088f720c1f30e5c54a56e385984ebd11d6855b14d6158f8833771501709e68';
  const v1OutputPubkeyHex =
      '46db9bd8d491531b2e783d32e07acb0624093fcdad75573e7e6da39ac21d0c13';
  // The block-level ECDH tweak (A_sum * input_hash) — the INPUT to scanning,
  // used to derive the shared secret. Not to be confused with the per-match
  // spend-key tweak scan_transaction returns, which is a different value
  // computed FROM this one plus the receiver's own key material.
  const blockTweakHex =
      '0302cc2a75db0e06919f9d3312c17c831b68ff1ead95498a529fd366d64921e3c0';
  const v2Blob112Base64 =
      'cAAAAAFonnABFXcziI8V1hRbhdYRvU6YheNWSsXlMB8Mco8IOAMCzCp12w4GkZ+dMxLBfIMbaP8erZVJilKf02bWSSHjwAEARtub2NSRUxsueD0y4HrLBiQJP82tdVc+fm2jmsIdDBM=';
  const v2Blob1EmptyBase64 = 'AQAAAAA='; // height 1, tx_count 0

  group('scanBlock vs scanOutputs identity (real electrs-tweaks fixture)', () {
    test('v1 path (production scanOutputs) matches the fixture', () {
      final v1Result = scanOutputs([[v1OutputPubkeyHex]], blockTweakHex, receiver);
      expect(v1Result, isNotEmpty);
      expect((v1Result['None'] as Map).containsKey(v1OutputPubkeyHex), isTrue);
    });

    test('v2 path (ScanSession.scanBlock) matches the fixture and agrees with v1', () {
      final v1Result = scanOutputs([[v1OutputPubkeyHex]], blockTweakHex, receiver);
      final v1SpendTweak = (v1Result['None'] as Map)[v1OutputPubkeyHex];

      final session = ScanSession.create(receiver);
      addTearDown(session.dispose);

      final matches = session.scanBlock(base64Decode(v2Blob112Base64));

      expect(matches, hasLength(1));
      final match = matches.first as Map<String, dynamic>;
      expect(match['height'], 112);
      expect(match['txid'], v1TxidDisplayHex,
          reason: 'v2 txid must already be reversed to display-hex order by the decoder');
      expect(match['vout'], 0);
      expect(match['label'], 'None');
      expect(match['output_pubkey'], v1OutputPubkeyHex);
      expect(match['tweak'], v1SpendTweak,
          reason: 'v2 decode-and-scan must agree with the independent v1 parse-then-scan path '
              'on the derived spend-key tweak, not just the match itself');
    });

    test('a negative-control receiver does not match either path', () {
      final otherReceiver = Receiver('33' * 32, bSpendCompressedHex, false, const [], 0);

      final v1Result = scanOutputs([[v1OutputPubkeyHex]], blockTweakHex, otherReceiver);
      expect(v1Result, isEmpty);

      final session = ScanSession.create(otherReceiver);
      addTearDown(session.dispose);
      expect(session.scanBlock(base64Decode(v2Blob112Base64)), isEmpty);
    });
  });

  group('scanBlock decoder edge cases', () {
    test('a zero-tx block (the empty-tail bookmark case) decodes to no matches', () {
      final session = ScanSession.create(receiver);
      addTearDown(session.dispose);
      expect(session.scanBlock(base64Decode(v2Blob1EmptyBase64)), isEmpty);
    });

    test('a truncated block throws instead of crashing', () {
      final session = ScanSession.create(receiver);
      addTearDown(session.dispose);

      final fullBlock = base64Decode(v2Blob112Base64);
      // Cut off mid-header: not even a full u32 height is present.
      final truncated = fullBlock.sublist(0, 2);

      expect(() => session.scanBlock(truncated), throwsA(isA<StateError>()));
    });

    test('a block whose declared tx_count exceeds the actual bytes throws', () {
      final session = ScanSession.create(receiver);
      addTearDown(session.dispose);

      // Valid height, but tx_count says 5 with nothing else following.
      final malformed = Uint8List.fromList(base64Decode(v2Blob1EmptyBase64));
      malformed[4] = 5; // was tx_count = 0
      expect(() => session.scanBlock(malformed), throwsA(isA<StateError>()));
    });
  });
}
