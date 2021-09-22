import assert from 'assert'
import * as base32 from 'hi-base32'
import { sscanf } from 'scanf'
import { ecdsaVerify } from 'secp256k1'
import {Multiaddr} from 'multiaddr'
import base64url from 'base64url'
import { keccak256 } from 'js-sha3';

type MatreeRootValues = {
  maRoot: string
  lRoot: string
  seq: number
  signature: string
}

type MatreeTreeValues = {
  publicKey: string
  domain: string
}

/**
 * Facilitate the decoding of matree DNS entry as defined in
 * [25/LIBP2P-DNS-DISCOVERY](https://rfc.vac.dev/spec/25/).
 */
export class Matree {
  public static readonly MultiaddrPrefix = 'ma:'
  public static readonly LinkPrefix = 'matree:'
  public static readonly BranchPrefix = 'matree-branch:'
  public static readonly RootPrefix = 'matree-root:'

  /**
   * Converts a Matree Multiaddr entry string into a Multiaddr.
   */
  static parseMultiaddr(ma: string): Multiaddr {
    assert(
      ma.startsWith(this.MultiaddrPrefix),
      `String encoded Matree Multiaddr entry must start with '${this.MultiaddrPrefix}'`
    )

    return new Multiaddr(ma.slice(this.MultiaddrPrefix.length))
  }

  /**
   * Extracts the branch subdomain referenced by a DNS tree root string after verifying
   * the root record signature with its base32 compressed public key.
   *
   * @param root The string value present a root entry TXT DNS record.
   * @param publicKey The base32 encoding of the compressed 32-bytes binary
   * public key that signs the list
   */
  static parseAndVerifyRoot(root: string, publicKey: string): string {
    assert(
      root.startsWith(this.RootPrefix),
      `Matree root entry must start with '${this.RootPrefix}'`
    )

    const rootVals = sscanf(
      root,
      `${this.RootPrefix}v1 m=%s l=%s seq=%d sig=%s`,
      'maRoot',
      'lRoot',
      'seq',
      'signature'
    ) as MatreeRootValues

    assert.ok(rootVals.maRoot, "Could not parse 'm' value from Matree root entry")
    assert.ok(rootVals.lRoot, "Could not parse 'l' value from Matree root entry")
    assert.ok(rootVals.seq, "Could not parse 'seq' value from Matree root entry")
    assert.ok(rootVals.signature, "Could not parse 'sig' value from Matree root entry")

    const decodedPublicKey = base32.decode.asBytes(publicKey)

    // The signature is a 65-byte secp256k1 over the keccak256 hash
    // of the record content, excluding the `sig=` part, encoded as URL-safe base64 string
    // (Trailing recovery bit must be trimmed to pass `ecdsaVerify` method)
    const signedComponent = root.split(' sig')[0]
    const signedComponentBuffer = Buffer.from(signedComponent)
    const signedComponentHash = Buffer.from(keccak256.arrayBuffer(signedComponentBuffer))
    const signatureBuffer = base64url.toBuffer(rootVals.signature).slice(0, 64)
    const keyBuffer = Buffer.from(decodedPublicKey)

    const isVerified = ecdsaVerify(signatureBuffer, signedComponentHash, keyBuffer)

    assert(isVerified, 'Unable to verify Matree root signature')

    return rootVals.maRoot
  }

  /**
   * Returns the public key and top level domain of an Matree link entry.
   * The domain is the starting point for traversing a set of linked DNS TXT records
   * and the public key is used to verify the root entry record
   *
   * @param  {string} tree Link entry
   * @return {MatreeTreeValues}
   */
  static parseLink(tree: string): MatreeTreeValues {
    assert(
      tree.startsWith(this.LinkPrefix),
      `Matree link entry must start with '${this.LinkPrefix}'`
    )

    const treeVals = sscanf(
      tree,
      `${this.LinkPrefix}//%s@%s`,
      'publicKey',
      'domain'
    ) as MatreeTreeValues

    assert.ok(treeVals.publicKey, 'Could not parse public key from Matree link entry')
    assert.ok(treeVals.domain, 'Could not parse domain from Matree link entry')

    return treeVals
  }

  /**
   * Returns subdomains listed in an Matree branch entry. These in turn lead to
   * either further branch entries or Matree records.
   */
  static parseBranch(branch: string): string[] {
    assert(
      branch.startsWith(this.BranchPrefix),
      `Matree branch entry must start with '${this.BranchPrefix}'`
    )

    return branch.split(this.BranchPrefix)[1].split(',')
  }
}
