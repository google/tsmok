# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Simple implementation of SHA256 and SHA224."""


class Sha:
  """Base class for SHA 224 and 256."""

  blocksize = 64

  CH = lambda x, y, z: (z ^ (x & (y ^ z)))
  MAJ = lambda x, y, z: (((x | y) & z) | (x & y))
  R = lambda x, n: (x & 0xffffffff) >> n

  def __init__(self, digestsize, digests):
    self.state_digests = digests
    self.count_lo = 0
    self.count_hi = 0
    self.digestsize = digestsize
    self.data = [0] * self.blocksize
    self.local = 0

  def _ror(self, x, y):
    return (((x & 0xffffffff) >> (y & 31)) |
            (x << (32 - (y & 31)))) & 0xffffffff

  def _rnd(self, a, b, c, d, e, f, g, h, ki, wi):
    t0 = h + self._sigma1(e) + Sha.CH(e, f, g) + ki + wi
    t1 = self._sigma0(a) + Sha.MAJ(a, b, c)
    d += t0
    h = t0 + t1
    return d & 0xffffffff, h & 0xffffffff

  def _sigma0(self, x):
    return self._ror(x, 2) ^ self._ror(x, 13) ^ self._ror(x, 22)

  def _sigma1(self, x):
    return self._ror(x, 6) ^ self._ror(x, 11) ^ self._ror(x, 25)

  def _gamma0(self, x):
    return self._ror(x, 7) ^ self._ror(x, 18) ^ Sha.R(x, 3)

  def _gamma1(self, x):
    return self._ror(x, 17) ^ self._ror(x, 19) ^ Sha.R(x, 10)

  def transform(self):
    """Makes SHA data transformation."""

    w = []
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    for i in range(0, 16):
      w.append((self.data[4*i]<<24) + (self.data[4*i+1]<<16) +
               (self.data[4*i+2]<<8) + self.data[4*i+3])

    for i in range(16, 64):
      w.append((self._gamma1(w[i - 2]) + w[i - 7] + self._gamma0(w[i - 15]) +
                w[i - 16]) & 0xffffffff)

    ss = self.state_digests.copy()
    offset = 3
    for i in range(64):
      fst = offset % 8
      snd = (offset + 4) % 8
      ss_off = fst + 5
      ss[fst], ss[snd] = self._rnd(ss[(ss_off + 0) % 8], ss[(ss_off + 1) % 8],
                                   ss[(ss_off + 2) % 8], ss[(ss_off + 3) % 8],
                                   ss[(ss_off + 4) % 8], ss[(ss_off + 5) % 8],
                                   ss[(ss_off + 6) % 8], ss[(ss_off + 7) % 8],
                                   k[i], w[i])
      offset += 7

    dig = []
    for i, x in enumerate(self.state_digests):
      dig.append((x + ss[i]) & 0xffffffff)
    self.state_digests = dig

  def update(self, data: bytes):
    """Update internal state with data.

    Args:
      data: New data to update SHA sum
    """

    count = len(data)
    idx = 0
    clo = (self.count_lo + (count << 3)) & 0xffffffff
    if clo < self.count_lo:
      self.count_hi += 1
    self.count_lo = clo
    self.count_hi += (count >> 29)

    if self.local:
      i = self.blocksize - self.local
      if i > count:
        i = count

      self.data[self.local:self.local + i] = data[idx:idx + i]

      count -= i
      idx += i

      self.local += i
      if self.local != self.blocksize:
        return

      self.transform()
      self.local = 0

    while count >= self.blocksize:
      self.data = list(data[idx:idx + self.blocksize])
      count -= self.blocksize
      idx += self.blocksize
      self.transform()

    pos = self.local
    self.data[pos:pos+count] = data[idx:idx + count]
    self.local = count

  def copy(self):
    """Makes duplicate of internal state."""

    other = self.__class__.__new__(self.__class__)
    other.state_digests = self.state_digests
    other.count_lo = self.count_lo
    other.count_hi = self.count_hi
    other.data = self.data
    other.local = self.local
    other.blocksize = self.blocksize
    other.digestsize = self.digestsize

    return other

  def get_interim_digest(self):
    dig = []
    for i in self.state_digests:
      dig.extend([((i>>24) & 0xff), ((i>>16) & 0xff), ((i>>8) & 0xff),
                  (i & 0xff)])
    return bytes(dig)

  def digest(self):
    """Returns final digest for SHA."""

    h = self.copy()

    lo_bit_count = h.count_lo
    hi_bit_count = h.count_hi
    count = (lo_bit_count >> 3) & 0x3f
    h.data[count] = 0x80
    count += 1
    # zero the bytes in data after the count
    h.data = h.data[:count] + ([0] * (h.blocksize - count))
    if count > h.blocksize - 8:
      h.transform()
      # zero bytes in data
      h.data = [0] * h.blocksize

    h.data[56] = (hi_bit_count >> 24) & 0xff
    h.data[57] = (hi_bit_count >> 16) & 0xff
    h.data[58] = (hi_bit_count >>  8) & 0xff
    h.data[59] = (hi_bit_count >>  0) & 0xff
    h.data[60] = (lo_bit_count >> 24) & 0xff
    h.data[61] = (lo_bit_count >> 16) & 0xff
    h.data[62] = (lo_bit_count >>  8) & 0xff
    h.data[63] = (lo_bit_count >>  0) & 0xff

    h.transform()

    dig = []
    for i in h.state_digests:
      dig.extend([((i>>24) & 0xff), ((i>>16) & 0xff), ((i>>8) & 0xff),
                  (i & 0xff)])
    return bytes(dig)


class Sha256(Sha):

  def __init__(self):
    Sha.__init__(self, 32, [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19])


class Sha224(Sha):

  def __init__(self):
    Sha.__init__(self, 28, [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4])
