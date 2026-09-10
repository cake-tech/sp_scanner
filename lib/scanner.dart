// ignore_for_file: non_constant_identifier_names
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:sp_scanner/generated_bindings.dart';
import 'package:blockchain_utils/blockchain_utils.dart' show BytesUtils;

DynamicLibrary load(name) {
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$name.so');
  } else if (Platform.isIOS || Platform.isMacOS) {
    return DynamicLibrary.open('$name.framework/$name');
  } else if (Platform.isWindows) {
    return DynamicLibrary.open('$name.dll');
  } else {
    return DynamicLibrary.process();
  }
}

final dl = load('sp_scanner');
final lib = NativeLibrary(dl);

class Receiver {
  final String bScan;
  final String BSpend;
  final bool isTestnet;
  final List<int> labels;
  final int labelsLen;

  Receiver(this.bScan, this.BSpend, this.isTestnet, this.labels, this.labelsLen);

  Map<String, dynamic> toJson() {
    return {
      'bScan': bScan,
      'BSpend': BSpend,
      'isTestnet': isTestnet,
      'labels': labels,
      'labelsLen': labelsLen,
    };
  }

  static Receiver fromJson(Map<String, dynamic> json) {
    return Receiver(
      json['bScan'],
      json['BSpend'],
      json['isTestnet'],
      List<int>.from(json['labels']),
      json['labelsLen'],
    );
  }
}

Pointer<OutputData> createOutputDataStruct(String outputToCheck) {
  final outputBytes = BytesUtils.fromHexString(outputToCheck);
  final Pointer<Uint8> outputToCheckPtr = calloc<Uint8>(outputBytes.length);
  final outputToCheckList = outputToCheckPtr.asTypedList(outputBytes.length);
  outputToCheckList.setAll(0, outputBytes);

  final result = calloc<OutputData>();
  result.ref.pubkey_bytes = outputToCheckPtr;
  return result;
}

void freeOutputDataStruct(Pointer<OutputData> voutDataPtr) {
  calloc.free(voutDataPtr.ref.pubkey_bytes);
  calloc.free(voutDataPtr);
}

Pointer<ReceiverData> createReceiverDataStruct(
  String bScan,
  String BSpend,
  bool isTestnet,
  List<int> labels,
  int labelsLen,
) {
  final Pointer<Uint8> bScanPtr = calloc<Uint8>(bScan.length);
  final bScanList = bScanPtr.asTypedList(bScan.length);
  bScanList.setAll(0, BytesUtils.fromHexString(bScan));

  final Pointer<Uint8> bSpendPtr = calloc<Uint8>(BSpend.length);
  final BSpendList = bSpendPtr.asTypedList(BSpend.length);
  BSpendList.setAll(0, BytesUtils.fromHexString(BSpend));

  final Pointer<Uint32> labelsPtr = calloc<Uint32>(labels.length);
  final labelsList = labelsPtr.asTypedList(labels.length);
  labelsList.setAll(0, labels);

  final result = calloc<ReceiverData>();
  result.ref
    ..b_scan_bytes = bScanPtr
    ..B_spend_bytes = bSpendPtr
    ..is_testnet = isTestnet
    ..labels = labelsPtr
    ..labels_len = labelsLen;
  return result;
}

void freeReceiverDataStruct(Pointer<ReceiverData> receiverDataPtr) {
  calloc.free(receiverDataPtr.ref.b_scan_bytes);
  calloc.free(receiverDataPtr.ref.B_spend_bytes);
  calloc.free(receiverDataPtr.ref.labels);
  calloc.free(receiverDataPtr);
}

Pointer<Int8> callApiScanOutputs(
    List<dynamic> outputsToCheck, String tweakDataForRecipient, Receiver receiver) {
  final pointers = calloc<Pointer<OutputData>>(outputsToCheck.length);
  for (int i = 0; i < outputsToCheck.length; i++) {
    pointers[i] = createOutputDataStruct(outputsToCheck[i][0].toString());
  }

  final pointersReceiver = createReceiverDataStruct(
    receiver.bScan,
    receiver.BSpend,
    receiver.isTestnet,
    receiver.labels,
    receiver.labelsLen,
  );

  final tweakBytes = BytesUtils.fromHexString(tweakDataForRecipient);
  final tweakPtr = calloc<Uint8>(tweakBytes.length);
  final tweakList = tweakPtr.asTypedList(tweakBytes.length);
  tweakList.setAll(0, tweakBytes);

  final paramData = calloc<ParamData>();
  paramData.ref
    ..outputs_data = pointers
    ..outputs_data_len = outputsToCheck.length
    ..tweak_bytes = tweakPtr
    ..receiver_data = pointersReceiver;

  // Call the Rust function with ParamData
  final result = lib.api_scan_outputs(paramData);

  // Cleanup
  for (int i = 0; i < outputsToCheck.length; i++) {
    freeOutputDataStruct(pointers[i]);
  }
  freeReceiverDataStruct(pointersReceiver);
  calloc.free(pointers);
  calloc.free(tweakPtr);
  calloc.free(paramData);

  return result;
}

typedef FreePointerFunc = Int8 Function(Pointer<Int8>);
typedef FreePointer = int Function(Pointer<Int8>);

final freePointer = dl.lookupFunction<FreePointerFunc, FreePointer>('free_pointer');

Map<String, dynamic> interpretBytesVec(Pointer<Int8> pointer) {
  final jsonString = pointer.cast<Utf8>().toDartString();

  final result = jsonDecode(jsonString) as Map<String, dynamic>;

  freePointer(pointer);

  return result;
}

Map<String, dynamic> scanOutputs(
  List<dynamic> outputsToCheck,
  String tweakDataForRecipient,
  Receiver receiver,
) {
  return interpretBytesVec(callApiScanOutputs(outputsToCheck, tweakDataForRecipient, receiver));
}

/// A persistent native scan session: the `Secp256k1` context, `Receiver`,
/// and labels are built once (in [ScanSession.create]) and reused across
/// every [scan] call, instead of being rebuilt on every call the way
/// [scanOutputs] does. Scan math and results are identical to [scanOutputs]
/// for the same inputs.
///
/// Exactly one session per calling isolate — the underlying native state is
/// not safe to share across isolates/threads.
///
/// There is no finalizer: callers own the native memory and MUST call
/// [dispose] exactly once when done with the session (e.g. before the
/// isolate holding it exits). A hard `Isolate.kill` will leak the native
/// session — the caller must cooperatively stop and dispose first.
class ScanSession {
  final Pointer<SpSession> _session;

  ScanSession._(this._session);

  /// Creates a session for [receiver]. Throws [StateError] if the receiver
  /// data is malformed (never expected for real wallet keys, but the native
  /// side treats this as untrusted input rather than panicking).
  factory ScanSession.create(Receiver receiver) {
    final receiverData = createReceiverDataStruct(
      receiver.bScan,
      receiver.BSpend,
      receiver.isTestnet,
      receiver.labels,
      receiver.labelsLen,
    );

    final session = lib.api_session_create(receiverData);
    freeReceiverDataStruct(receiverData);

    if (session == nullptr) {
      throw StateError('sp_scanner: api_session_create failed on the given receiver data');
    }

    return ScanSession._(session);
  }

  /// Scans [outputsToCheck] (a list of single-element `[pubkeyHex]` lists,
  /// matching [scanOutputs]'s shape) against [tweakDataForRecipient]. Returns
  /// `{label: {pubkey: tweak}}`, or `{}` for no match. Throws [StateError] on
  /// malformed input (e.g. an invalid tweak) rather than propagating a
  /// native panic.
  Map<String, dynamic> scan(List<dynamic> outputsToCheck, String tweakDataForRecipient) {
    final pointers = calloc<Pointer<OutputData>>(outputsToCheck.length);
    for (int i = 0; i < outputsToCheck.length; i++) {
      pointers[i] = createOutputDataStruct(outputsToCheck[i][0].toString());
    }

    final tweakBytes = BytesUtils.fromHexString(tweakDataForRecipient);
    final tweakPtr = calloc<Uint8>(tweakBytes.length);
    tweakPtr.asTypedList(tweakBytes.length).setAll(0, tweakBytes);

    final result = lib.api_session_scan(_session, pointers, outputsToCheck.length, tweakPtr);

    for (int i = 0; i < outputsToCheck.length; i++) {
      freeOutputDataStruct(pointers[i]);
    }
    calloc.free(pointers);
    calloc.free(tweakPtr);

    if (result == nullptr) {
      throw StateError('sp_scanner: api_session_scan failed on the given tweak/output data');
    }

    return interpretBytesVec(result);
  }

  /// Decodes+scans one `blockchain.tweaks.subscribe` v2 binary block record
  /// against this session. [blockBytes] is the raw block bytes — the wire
  /// blob is base64 (see electrs-tweaks's `doc/tweaks_v2_protocol.md`), so
  /// callers must `base64Decode` it before calling this. One block per
  /// server push notification, so one call here per notification (the
  /// server never batches multiple blocks into one message).
  ///
  /// Returns a list of match records, each shaped `{height, txid, vout,
  /// label, output_pubkey, tweak}` (`txid` already in conventional
  /// display-hex order, not the wire's internal/consensus order — see the
  /// txid byte-order note in the protocol doc). An empty list means no
  /// match, the overwhelmingly common case. Throws [StateError] on a
  /// malformed block (server bug, or a version mismatch — this must only
  /// ever be called with bytes produced by a server that negotiated
  /// `protocol_version: 2`) rather than propagating a native panic.
  List<dynamic> scanBlock(Uint8List blockBytes) {
    final blockPtr = calloc<Uint8>(blockBytes.length);
    blockPtr.asTypedList(blockBytes.length).setAll(0, blockBytes);

    final result = lib.api_session_scan_block_v2(_session, blockPtr, blockBytes.length);
    calloc.free(blockPtr);

    if (result == nullptr) {
      throw StateError('sp_scanner: api_session_scan_block_v2 failed on the given block bytes');
    }

    final jsonString = result.cast<Utf8>().toDartString();
    freePointer(result);
    return jsonDecode(jsonString) as List<dynamic>;
  }

  /// Releases the native session. Must be called exactly once; the session
  /// must not be used afterward.
  void dispose() {
    lib.api_session_destroy(_session);
  }
}

/// Highest `blockchain.tweaks.subscribe` wire-protocol version this build's
/// native decoder understands. Capability negotiation must use
/// `min(serverAdvertisedVersion, maxWireVersion())`, never the server's
/// advertised version alone.
int maxWireVersion() => lib.api_max_wire_version();
