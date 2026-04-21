"""Implementation of GSMA eSIM RSP (Remote SIM Provisioning) as per SGP22 v3.0"""

# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from typing import Optional
import shelve

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.hazmat.primitives import hashes # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec # noqa: E402

from cryptography import x509
from osmocom.utils import b2h
from osmocom.tlv import bertlv_parse_one_rawtag, bertlv_return_one_rawtlv

from pySim.esim import compile_asn1_subdir

asn1 = compile_asn1_subdir('rsp')

class RspSessionState:
    """Encapsulates the state of a RSP session.  It is created during the initiateAuthentication
    and subsequently used by further API calls using the same transactionId.  The session state
    is removed either after cancelSession or after notification.
    TODO: add some kind of time based expiration / garbage collection."""
    def __init__(self, transactionId: str, serverChallenge: bytes, ci_cert_id: bytes):
        self.transactionId = transactionId
        self.serverChallenge = serverChallenge
        #  used at a later point between API calls
        self.ci_cert_id = ci_cert_id
        self.euicc_cert: Optional[x509.Certificate] = None
        self.eum_cert: Optional[x509.Certificate] = None
        self.eid: Optional[bytes] = None
        self.profileMetadata: Optional['ProfileMetadata'] = None
        self.smdpSignature2_do = None
        # really only needed while processing getBoundProfilePackage request?
        self.euicc_otpk: Optional[bytes] = None
        self.smdp_ot: Optional[ec.EllipticCurvePrivateKey] = None
        self.smdp_otpk: Optional[bytes] = None
        self.host_id: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        #* Added state values for zk-eSIM 
        self.euicc_challenge: Optional[bytes] = None            #* Added EUICC challenge (N_u)
        self.h_cert: Optional[bytes] = None                     #* Added hashed pseudonym ceritificate (h_cert)
        self.t_i: Optional[bytes] = None                        #* Added authorisation token (ie T_i)
        self.L_spent: Optional[MerkleAccumulator] = None        #* Added accumulator to the RSP (L_spent)
        self.root_spent: Optional[bytes] = None                 #* Added hash of L_spent (root_spent)
        self.L_auth: Optional[MerkleAccumulator] = None         #* Added accumulator for auth tokens (L_auth)
        self.root_auth: Optional[bytes] = None                  #* Added hash of L_auth (root_auth)
        self.pi_inc: Optional[list] = None                      #* Added proof of inclusion in accumulator (π_inc)
        #* Pseudonym Id values (both pid and the hash of pid - H_pid)
        self.pid: Optional[bytes] = None                        #* Added per session pseudonym (pid)
        self.h_pid: Optional[bytes] = None                      #* Added hash of pid (H_pid)
        #* MNO key and identifier values    
        #! self.sk_mno: Optional[bytes] = None                  # Not used but needed to generate the public key               
        self.pk_mno: Optional[ec.EllipticCurvePublicKey] = None #* Added public key for the mno - may need to be hardcoded
        self.mnoid: Optional[bytes] = None                      #* Added the mno id - endcoded string as utf-8
        self.auth_tok: Optional[bytes] = None                   #* Added authorisation token (T_i) - one time token
        self.expiry: Optional[bytes] = None                     #* Added expiry of the auth_token for the T_i verification step
        #* MNO-based signatures
        self.sig_cred: Optional[bytes] = None                   #* Added signature over (H_pid, h_cert, mnoid)
        self.sig_root: Optional[bytes] = None                   #* Added signature over (root_auth, sig^MNO_root)
        


    def __getstate__(self):
        """helper function called when pickling the object to persistent storage.  We must pickel all
        members that are not pickle-able."""
        state = self.__dict__.copy()
        # serialize eUICC certificate as DER
        if state.get('euicc_cert', None):
            state['_euicc_cert'] = self.euicc_cert.public_bytes(Encoding.DER)
            del state['euicc_cert']
        # serialize EUM certificate as DER
        if state.get('eum_cert', None):
            state['_eum_cert'] = self.eum_cert.public_bytes(Encoding.DER)
            del state['eum_cert']
        # serialize one-time SMDP private key to integer + curve
        if state.get('smdp_ot', None):
            state['_smdp_otsk'] = self.smdp_ot.private_numbers().private_value
            state['_smdp_ot_curve'] = self.smdp_ot.curve
            del state['smdp_ot']
        # serialize MNO public key for zk mode session persistence
        if state.get('pk_mno', None):
            state['_pk_mno'] = self.pk_mno.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            del state['pk_mno']
        return state

    def __setstate__(self, state):
        """helper function called when unpickling the object from persistent storage. We must recreate all
        members from the state generated in __getstate__ above."""
        # restore eUICC certificate from DER
        if '_euicc_cert' in state:
            self.euicc_cert = x509.load_der_x509_certificate(state['_euicc_cert'])
            del state['_euicc_cert']
        else:
            self.euicc_cert = None
        # restore EUM certificate from DER
        if '_eum_cert' in state:
            self.eum_cert = x509.load_der_x509_certificate(state['_eum_cert'])
            del state['_eum_cert']
        # restore one-time SMDP private key from integer + curve
        if state.get('_smdp_otsk', None):
            self.smdp_ot = ec.derive_private_key(state['_smdp_otsk'], state['_smdp_ot_curve'])
            # FIXME: how to add the public key from smdp_otpk to an instance of EllipticCurvePrivateKey?
            del state['_smdp_otsk']
            del state['_smdp_ot_curve']
        # restore MNO public key for zk mode
        if '_pk_mno' in state:
            self.pk_mno = load_der_public_key(state['_pk_mno'])
            del state['_pk_mno']
        else:
            self.pk_mno = None
        # automatically recover all the remaining state
        self.__dict__.update(state)

    #* Added to enable the h_cert to be stored in the session state
    def setHCert(self, hCert: bytes):
        self.h_cert = hCert


class RspSessionStore:
    """A wrapper around the database-backed storage 'shelve' for storing RspSessionState objects.
    Can be configured to use either file-based storage or in-memory storage.
    We use it to store RspSessionState objects indexed by transactionId."""

    def __init__(self, filename: Optional[str] = None, in_memory: bool = False):
        self._in_memory = in_memory

        if in_memory:
            self._shelf = shelve.Shelf(dict())
        else:
            if filename is None:
                raise ValueError("filename is required for file-based session store")
            self._shelf = shelve.open(filename)

    # dunder magic
    def __getitem__(self, key):
        return self._shelf[key]

    def __setitem__(self, key, value):
        self._shelf[key] = value

    def __delitem__(self, key):
        del self._shelf[key]

    def __contains__(self, key):
        return key in self._shelf

    def __iter__(self):
        return iter(self._shelf)

    def __len__(self):
        return len(self._shelf)

    # everything else
    def __getattr__(self, name):
        """Delegate attribute access to the underlying shelf object."""
        return getattr(self._shelf, name)

    def close(self):
        """Close the session store."""
        if hasattr(self._shelf, 'close'):
            self._shelf.close()
        if self._in_memory:
            # For in-memory store, clear the reference
            self._shelf = None

    def sync(self):
        """Synchronize the cache with the underlying storage."""
        if hasattr(self._shelf, 'sync'):
            self._shelf.sync()


def extract_euiccSigned1(authenticateServerResponse: bytes) -> bytes:
    """Extract the raw, DER-encoded binary euiccSigned1 field from the given AuthenticateServerResponse. This
    is needed due to the very peculiar SGP.22 notion of signing sections of DER-encoded ASN.1 objects."""
    rawtag, l, v, remainder = bertlv_parse_one_rawtag(authenticateServerResponse)
    if len(remainder):
        raise ValueError('Excess data at end of TLV')
    if rawtag != 0xbf38:
        raise ValueError('Unexpected outer tag: %s' % b2h(rawtag))
    rawtag, l, v1, remainder = bertlv_parse_one_rawtag(v)
    if rawtag != 0xa0:
        raise ValueError('Unexpected tag where CHOICE was expected')
    rawtag, l, tlv2, remainder = bertlv_return_one_rawtlv(v1)
    if rawtag != 0x30:
        raise ValueError('Unexpected tag where SEQUENCE was expected')
    return tlv2

def extract_euiccSigned2(prepareDownloadResponse: bytes) -> bytes:
    """Extract the raw, DER-encoded binary euiccSigned2 field from the given prepareDownloadrResponse. This is
    needed due to the very peculiar SGP.22 notion of signing sections of DER-encoded ASN.1 objects."""
    rawtag, l, v, remainder = bertlv_parse_one_rawtag(prepareDownloadResponse)
    if len(remainder):
        raise ValueError('Excess data at end of TLV')
    if rawtag != 0xbf21:
        raise ValueError('Unexpected outer tag: %s' % b2h(rawtag))
    rawtag, l, v1, remainder = bertlv_parse_one_rawtag(v)
    if rawtag != 0xa0:
        raise ValueError('Unexpected tag where CHOICE was expected')
    rawtag, l, tlv2, remainder = bertlv_return_one_rawtlv(v1)
    if rawtag != 0x30:
        raise ValueError('Unexpected tag where SEQUENCE was expected')
    return tlv2

def hash_fn(input):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    return digest.finalize()

class MerkleAccumulator():

    def __init__(self):
        self.leaves = {}
        self.root = []

    def _compute_root(self):
        nodes = list(self.leaves.values())
        if not nodes:
            self.root = None
            return

        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                next_level.append(hash_fn(left+right))
            nodes = next_level
        self.root = nodes[0]

    def add(self, element: str):
        if element in self.leaves:
            return 
        leaf_hash = hash_fn(element.encode())
        self.leaves[element] = leaf_hash
        self._compute_root()

    def remove(self, element: str):
        if element in self.leaves:
            del self.leaves[element]
            self._compute_root()

    def get_root(self):
        return self.root
    
    def generateProof(self, element: str):
        """
        Generate a simple membership proof.
        Returns the path of sibling hashes from leaf to root.
        """
        if element not in self.leaves:
            return None
        nodes = list(self.leaves.values())
        index = list(self.leaves.keys()).index(element)
        proof = []
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                next_level.append(hash_fn(left+right))
                if i <= index < i + 2:
                    sibling = right if i == index else left
                    proof.append(sibling)
            index = index // 2
            nodes = next_level
        return proof

    @staticmethod
    def verifyProof(element: str, proof: list, root: bytes) -> bool:
        """Verify membership proof for an element."""
        current = hash_fn(element.encode())
        for sibling in proof:
            if current < sibling:
                current = hash_fn(current + sibling)
            else:
                current = hash_fn(sibling + current)
        return current == root
