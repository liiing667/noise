package noise

import (
	"bytes"
	"reflect"

	. "gopkg.in/check.v1"
)

// handshakeSnapshot captures every HandshakeState field that ReadMessage is
// allowed to mutate, so a failed call can be proven to leave the state
// untouched.
type handshakeSnapshot struct {
	ss          symmetricState
	e           DHKey
	rs          []byte
	re          []byte
	psk         []byte
	shouldWrite bool
	msgIdx      int
}

func snapshotHandshake(hs *HandshakeState) handshakeSnapshot {
	snap := handshakeSnapshot{
		ss:          hs.ss,
		e:           hs.e,
		shouldWrite: hs.shouldWrite,
		msgIdx:      hs.msgIdx,
	}
	snap.rs = append([]byte(nil), hs.rs...)
	snap.re = append([]byte(nil), hs.re...)
	snap.psk = append([]byte(nil), hs.psk...)
	snap.e.Private = append([]byte(nil), hs.e.Private...)
	snap.e.Public = append([]byte(nil), hs.e.Public...)
	snap.ss.ck = append([]byte(nil), hs.ss.ck...)
	snap.ss.h = append([]byte(nil), hs.ss.h...)
	// Checkpoint bookkeeping is internal and recreated on every ReadMessage;
	// it is not observable handshake state.
	snap.ss.prevCK = nil
	snap.ss.prevH = nil
	return snap
}

func (snap handshakeSnapshot) assertEquals(c *C, hs *HandshakeState) {
	after := snapshotHandshake(hs)
	// A rollback rebuilds the AEAD from the same key, so the Cipher interface
	// value may be a fresh pointer even though k/n and all derived state are
	// identical. Compare every observable field individually instead.
	same := snap.ss.k == after.ss.k &&
		snap.ss.n == after.ss.n &&
		snap.ss.invalid == after.ss.invalid &&
		snap.ss.hasK == after.ss.hasK &&
		bytes.Equal(snap.ss.ck, after.ss.ck) &&
		bytes.Equal(snap.ss.h, after.ss.h) &&
		bytes.Equal(snap.rs, after.rs) &&
		bytes.Equal(snap.re, after.re) &&
		bytes.Equal(snap.psk, after.psk) &&
		reflect.DeepEqual(snap.e, after.e) &&
		snap.shouldWrite == after.shouldWrite &&
		snap.msgIdx == after.msgIdx
	if !same {
		c.Fatalf("handshake state was not fully rolled back after the error:\nwant: %+v\ngot:  %+v", snap, after)
	}
}

func newIncRNG(start byte) *RandomInc {
	rng := new(RandomInc)
	*rng = RandomInc(start)
	return rng
}

// A payload authentication failure (AEAD tag mismatch) must roll the whole
// handshake back so the original message can be retried.
func (NoiseSuite) TestReadMessageRollbackPayloadAuth(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := newIncRNG(0)
	rngR := newIncRNG(1)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))

	snap := snapshotHandshake(hsI)
	corrupt := append([]byte(nil), msg...)
	corrupt[1]++
	_, _, _, err = hsI.ReadMessage(nil, corrupt)
	c.Assert(err, Not(IsNil))
	snap.assertEquals(c, hsI)

	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")
}

// A message shorter than the required key token must leave the state
// unchanged, including after the ephemeral key token would have been
// processed.
func (NoiseSuite) TestReadMessageRollbackShortMessage(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := newIncRNG(0)
	rngR := newIncRNG(1)

	staticR, _ := cs.GenerateKeypair(rngR)
	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNX,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeNX,
		Initiator:     false,
		StaticKeypair: staticR,
	})

	// -> e
	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	_, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)

	// <- e, dhee, s, dhes : truncate before the encrypted static key token.
	good, _, _, _ := hsR.WriteMessage(nil, nil)

	snap := snapshotHandshake(hsI)
	_, _, _, err = hsI.ReadMessage(nil, good[:32+16])
	c.Assert(err, Equals, ErrShortMessage)
	snap.assertEquals(c, hsI)

	res, _, _, err := hsI.ReadMessage(nil, good)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)
	c.Assert(bytes.Equal(hsI.PeerStatic(), staticR.Public), Equals, true)
}

// A failing DH operation must roll back the MixKey updates performed earlier
// in the same message.
func (NoiseSuite) TestReadMessageRollbackDHFailure(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := newIncRNG(0)
	rngR := newIncRNG(1)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	_, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)

	// <- e, dhee : a zero ephemeral is a low-order point and fails DH.
	bad := make([]byte, 32)

	snap := snapshotHandshake(hsI)
	_, _, _, err = hsI.ReadMessage(nil, bad)
	c.Assert(err, Not(IsNil))
	snap.assertEquals(c, hsI)

	good, _, _, _ := hsR.WriteMessage(nil, nil)
	res, _, _, err := hsI.ReadMessage(nil, good)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)
}

// Reading a second static key into an already set remote static key must fail
// and roll back everything the message had already changed.
func (NoiseSuite) TestReadMessageRollbackDuplicateStatic(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rngI := newIncRNG(0)
	rngR := newIncRNG(1)

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeIX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeIX,
		Initiator:     false,
		StaticKeypair: staticR,
	})

	// -> e, s
	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	// Build a genuine second message (e, dhee, dhse, s, dhes) for hsR, then
	// force hsR to read it while it already holds a remote static key.
	good, _, _, _ := hsR.WriteMessage(nil, nil)

	// Rewind hsR to the point where a second inbound message is expected,
	// then snapshot the state a genuine caller would be in before ReadMessage.
	hsR.msgIdx--
	snap := snapshotHandshake(hsR)
	_, _, _, err = hsR.ReadMessage(nil, good)
	c.Assert(err, ErrorMatches, ".*rs is not nil.*")
	snap.assertEquals(c, hsR)

	// The handshake remains usable: hsI consumes the genuine second message
	// and both peers finish the two-message IX handshake normally.
	_, _, _, err = hsI.ReadMessage(nil, good)
	c.Assert(err, IsNil)
	c.Assert(hsI.MessageIndex(), Equals, len(HandshakeIX.Messages))
	// hsR's only second-read attempt was the rolled-back error, so it remains
	// parked at message 1 with its pre-call state fully intact.
	c.Assert(hsR.MessageIndex(), Equals, snap.msgIdx)
	c.Assert(hsR.PeerStatic(), DeepEquals, staticI.Public)
}
