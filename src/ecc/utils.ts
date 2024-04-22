import { buf2hex, int2BytesBe } from "../shared/utils.ts";

export function int2Hex(number: bigint, prefix = true, pad = true): string {
  const padding = pad ? 32 : 1;
  const result = buf2hex(int2BytesBe(number, padding), false);

  if (prefix) {
    return `0x${result}`;
  }

  return result;
}
