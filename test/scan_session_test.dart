// Correctness gate for the persistent-session scan API (ScanSession) against
// the production stateless API (scanOutputs): both must agree byte-for-byte
// on real Silent Payment scan results.
//
// Ported from sp-scan-bench/bin/synthetic_test.dart (the investigation that
// designed the session API) — see sp-scan-bench/docs/adr/0005 and 0014 for
// why this is the required merge gate for the session API, and
// sp-scan-bench/docs/regtest_e2e.md for how the sender-side math here was
// validated against a real BIP-352 indexer.
import 'dart:convert';

import 'package:bip39/bip39.dart' as bip39;
import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:bitcoin_base/bitcoin_base.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sp_scanner/sp_scanner.dart';

const _seed =
    'nominee prepare verify canoe garage change diamond digital dad tower cliff acid cute dress rare vocal sleep alien useless smile lecture opinion size wash';

void main() {
  final seedBytes = bip39.mnemonicToSeed(_seed);
  final masterHD = Bip32Slip10Secp256k1.fromSeed(seedBytes);
  final bScan = ECPrivate.fromHex(masterHD.derivePath("m/352'/0'/0'/1'/0").privateKey.toHex());
  final bSpend = ECPrivate.fromHex(masterHD.derivePath("m/352'/0'/0'/0'/0").privateKey.toHex());
  final owner = SilentPaymentOwner.fromPrivateKeys(
      b_scan: bScan, b_spend: bSpend, network: BitcoinNetwork.mainnet);

  final bScanAdvanced =
      ECPrivate.fromHex(masterHD.derivePath("m/352'/0'/0'/1'/1").privateKey.toHex());
  final bSpendAdvanced =
      ECPrivate.fromHex(masterHD.derivePath("m/352'/0'/0'/0'/1").privateKey.toHex());

  group('ScanSession vs scanOutputs identity', () {
    test('default address: match + decoy rejection, identical across both scanners', () {
      final senderPriv = ECPrivate.fromHex(
          '1111111111111111111111111111111111111111111111111111111111111111');
      final senderPub = senderPriv.getPublic();
      final outpoint = Outpoint.fromBytes(List.filled(32, 0xff), 0);
      final builder = SilentPaymentBuilder(vinOutpoints: [outpoint], pubkeys: [senderPub]);
      final destination = SilentPaymentDestination(
        scanPubkey: owner.b_scan.getPublic(),
        spendPubkey: owner.B_spend,
        version: owner.version,
        network: BitcoinNetwork.mainnet,
        amount: 50000,
      );
      final outputs = builder.createOutputs([ECPrivateInfo(senderPriv, true)], [destination]);
      final p2tr = outputs.values.first.first.address;
      final outputPubkeyHex = p2tr.addressProgram;
      final tweakHex = builder.A_sum!.tweakMul(BigintUtils.fromBytes(builder.inputHash!)).toHex();

      final prepared = [
        [outputPubkeyHex],
        ['02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'], // decoy
      ];

      final receivers = [
        (owner.b_scan.toHex(), owner.B_spend.toHex()), // real receiver: must match
        (
          masterHD.derivePath("m/352'/1'/0'/1'/0").privateKey.toHex(),
          masterHD.derivePath("m/352'/1'/0'/0'/0").publicKey.toHex(),
        ), // negative-control receiver: must not match, on either scanner
      ];

      for (var r = 0; r < receivers.length; r++) {
        final (b, B) = receivers[r];
        final prod = scanOutputs(prepared, tweakHex, Receiver(b, B, false, const [], 0));

        final session = ScanSession.create(Receiver(b, B, false, const [], 0));
        final fast = session.scan(prepared, tweakHex);
        session.dispose();

        expect(jsonEncode(fast), jsonEncode(prod),
            reason: 'receiver $r: session scan result must byte-match scanOutputs');

        if (r == 0) {
          expect(prod, isNotEmpty, reason: 'the real receiver must match its own payment');
        } else {
          expect(prod, isEmpty, reason: 'the negative-control receiver must not match');
        }
      }
    });

    test('labeled address (index 1): match identical across both scanners', () {
      final senderPriv2 = ECPrivate.fromHex(
          '2222222222222222222222222222222222222222222222222222222222222222');
      final builder2 = SilentPaymentBuilder(
        vinOutpoints: [Outpoint.fromBytes(List.filled(32, 0xee), 1)],
        pubkeys: [senderPriv2.getPublic()],
      );
      final dest2 = SilentPaymentDestination(
        scanPubkey: bScanAdvanced.getPublic(),
        spendPubkey: bSpendAdvanced.getPublic(),
        version: 0,
        network: BitcoinNetwork.mainnet,
        amount: 30000,
      );
      final outp2 =
          builder2.createOutputs([ECPrivateInfo(senderPriv2, true)], [dest2]).values.first.first;
      final outPub2 = outp2.address.addressProgram;
      final tweak2 = builder2.A_sum!.tweakMul(BigintUtils.fromBytes(builder2.inputHash!)).toHex();

      final prepared2 = [
        [outPub2],
        ['03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
      ];

      final receiver = Receiver(
        bScanAdvanced.toHex(),
        bSpendAdvanced.getPublic().toHex(),
        false,
        [1],
        1,
      );
      final prod2 = scanOutputs(prepared2, tweak2, receiver);

      final session2 = ScanSession.create(receiver);
      final fast2 = session2.scan(prepared2, tweak2);
      session2.dispose();

      expect(jsonEncode(fast2), jsonEncode(prod2),
          reason: 'labeled-address session scan result must byte-match scanOutputs');
      expect(prod2, isNotEmpty, reason: 'the labeled address must match its own payment');
    });
  });

  group('ScanSession error handling (native-side validation, not Dart hex parsing)', () {
    // Well-formed hex of the right byte length, but not a valid secp256k1
    // scalar/point — reaches the native validation (SecretKey/PublicKey
    // ::from_slice) rather than failing earlier at Dart's hex decoding, so
    // this actually exercises the ADR-0006 null-on-malformed-input path.
    final invalidScalarHex = '00' * 32; // zero is not a valid secp256k1 scalar
    final invalidPointHex = '00' * 33; // not a valid compressed point encoding

    test('invalid scan-key bytes throw instead of crashing', () {
      expect(
        () => ScanSession.create(
            Receiver(invalidScalarHex, owner.B_spend.toHex(), false, const [], 0)),
        throwsA(isA<StateError>()),
      );
    });

    test('invalid tweak bytes throw instead of crashing', () {
      final session = ScanSession.create(Receiver(
        bScan.toHex(),
        owner.B_spend.toHex(),
        false,
        const [],
        0,
      ));
      addTearDown(session.dispose);

      expect(
        () => session.scan([
          [invalidPointHex.substring(0, 64)] // 32-byte x-only pubkey slot
        ], invalidPointHex),
        throwsA(isA<StateError>()),
      );
    });
  });

  test('maxWireVersion reports a supported version', () {
    expect(maxWireVersion(), greaterThanOrEqualTo(1));
  });
}
