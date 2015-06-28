(*
* OCaml binding for botan (http://botan.randombit.net)
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*)

open Ctypes
open Foreign

exception Botan_Error of int

(* TODO: translate error code to string *)
let result_or_exn rc res =
  match rc with
  | 0 -> res
  | _ as ec -> raise (Botan_Error ec)


module Botan = struct

  let version =
    let version_major =
      foreign "botan_version_major" (void @-> returning int32_t) in
    let version_minor =
      foreign "botan_version_minor" (void @-> returning int32_t) in
    let version_patch =
      foreign "botan_version_patch" (void @-> returning int32_t) in
    let major = Int32.to_int (version_major ()) in
    let minor = Int32.to_int (version_minor ()) in
    let patch = Int32.to_int (version_patch ()) in
    (major, minor, patch)

  let version_string =
    let version_string =
      foreign "botan_version_string" (void @-> returning string) in
    version_string ()

  let version_date =
    let version_datestamp =
      foreign "botan_version_datestamp" (void @-> returning int32_t) in
    Int32.to_int (version_datestamp ())

  let ffi_version =
    let ffi_version =
      foreign "botan_ffi_api_version" (void @-> returning int32_t) in
    Int32.to_int (ffi_version ())

  let hex_encode bin =
    let hex_encode =
      foreign "botan_hex_encode" (string @-> size_t @-> ptr char @-> uint32_t @-> returning int) in
    let bin_len = String.length bin in
    let hex_len = 2*bin_len in
    let hex = allocate_n char hex_len in
    let rc = hex_encode bin (Unsigned.Size_t.of_int bin_len) hex (Unsigned.UInt32.of_int 0) in
    result_or_exn rc (string_from_ptr hex hex_len)

  module Hash = struct
    type t = unit ptr
    let hash_t : t typ = ptr void

    let create name =
      let hash_init =
        foreign "botan_hash_init" (ptr hash_t @-> string @-> uint32_t @-> returning int) in
      let o = allocate_n ~count:1 hash_t in
      let rc = hash_init o name (Unsigned.UInt32.of_int 0) in
      result_or_exn rc (!@ o)

    let destroy hash =
      let hash_destroy =
        foreign "botan_hash_destroy" (hash_t @-> returning int) in
      let rc = hash_destroy hash in
      result_or_exn rc ()

    let output_length hash =
      let hash_output_length =
        foreign "botan_hash_output_length" (hash_t @-> ptr size_t @-> returning int) in
      let ol = allocate_n ~count:1 size_t in
      let rc = hash_output_length hash ol in
      result_or_exn rc (Unsigned.Size_t.to_int (!@ ol))

    let clear hash =
      let hash_clear =
        foreign "botan_hash_clear" (hash_t @-> returning int) in
      let rc = hash_clear hash in
      result_or_exn rc ()

    let update hash input =
      let hash_update =
        foreign "botan_hash_update" (hash_t @-> string @-> size_t @-> returning int) in
      let input_len = (String.length input) in
      let rc = hash_update hash input (Unsigned.Size_t.of_int input_len) in
      result_or_exn rc ()

    let final hash =
      let hash_final =
        foreign "botan_hash_final" (hash_t @-> ptr char @-> returning int) in
      let ol = output_length hash in
      let res = allocate_n ~count:ol char in
      let rc = hash_final hash res in
      result_or_exn rc (string_from_ptr res ol)

  end (* Hash *)

  module RNG = struct
    type t = unit ptr
    let rng_t : t typ = ptr void

    let create name =
      let rng_init =
        foreign "botan_rng_init" (ptr rng_t @-> string @-> uint32_t @-> returning int) in
      let o = allocate_n ~count:1 rng_t in
      let rc = rng_init o name (Unsigned.UInt32.of_int 0) in
      result_or_exn rc (!@ o)

    let destroy rng =
      let rng_destroy =
        foreign "botan_rng_destroy" (rng_t @-> returning int) in
      let rc = rng_destroy rng in
      result_or_exn rc ()

    let generate rng out_len =
      let rng_generate =
        foreign "botan_rng_get" (rng_t @-> ptr char @-> size_t @-> returning int) in
      let res = allocate_n ~count:out_len char in
      let rc = rng_generate rng res (Unsigned.Size_t.of_int out_len) in
      result_or_exn rc (string_from_ptr res out_len)

    let reseed rng bits =
      let rng_reseed =
        foreign "botan_rng_reseed" (rng_t @-> size_t @-> returning int) in
      let rc = rng_reseed rng (Unsigned.Size_t.of_int bits) in
      result_or_exn rc ()

    let update rng input =
      let rng_update =
        foreign "botan_rng_update" (rng_t @-> string @-> size_t @-> returning int) in
      let input_len = (String.length input) in
      let rc = rng_update rng input (Unsigned.Size_t.of_int input_len) in
      result_or_exn rc ()

  end (* RNG *)

end (* Botan *)

let () =
  let rng = Botan.RNG.create "user" in
  print_string (Botan.hex_encode (Botan.RNG.generate rng 11) ^ "\n")

let () =
  let (maj,min,patch) = Botan.version in
  let ver_str = Botan.version_string in
  print_string (Printf.sprintf "%d.%d.%d\n%s\n" maj min patch ver_str)

let () =
  let h = Botan.Hash.create "SHA-384" in
  begin
    Botan.Hash.update h "hi";
    print_string (Botan.hex_encode (Botan.Hash.final h) ^ "\n");
    Botan.Hash.destroy h
  end
