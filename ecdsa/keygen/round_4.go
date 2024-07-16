// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"
	sync "sync"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/vss"
	zkpsch "github.com/Safulet/tss-lib-private/v2/crypto/zkp/sch"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tracer"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"go.opentelemetry.io/otel/trace"
)

func (round *round4) Start(ctx context.Context) *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	var span trace.Span
	ctx, span = tracer.StartWithFuncSpan(ctx)
	defer span.End()

	common.TryEmitTSSRoundStartEvent(ctx, TaskName, "round4")
	defer common.TryEmitTSSRoundEndEvent(ctx, TaskName, "round4")

	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	rejectionSample := tss.GetRejectionSampleFunc(round.Version())
	// Fig 5. Output 1. / Fig 6. Output 1.
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		errChs := make(chan *tss.Error, 3)
		wg := sync.WaitGroup{}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.RidAllBz, big.NewInt(int64(j)))

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if ok := round.temp.r3msgpfmod[j].Verify(ctx, ContextJ, round.save.NTildej[j], rejectionSample); !ok {
				errChs <- round.WrapError(errors.New("proofMod verify failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if ok := round.temp.r3msgpffac[j].Verify(ctx, ContextJ, round.EC(), round.save.NTildej[j], round.save.NTildei, round.save.H1i, round.save.H2i, rejectionSample); !ok {
				errChs <- round.WrapError(errors.New("proofFac verify failed"), Pj)
			}
		}(j, Pj)

		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			share := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     round.temp.r3msgxij[j],
			}
			if ok := share.Verify(round.EC(), round.Threshold(), round.temp.r2msgVss[j]); !ok {
				errChs <- round.WrapError(errors.New("vss verify failed"), Pj)
			}

		}(j, Pj)

		wg.Wait()
		close(errChs)
		culprits := make([]*tss.PartyID, 0)
		for err := range errChs {
			culprits = append(culprits, err.Culprits()...)
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("round4: failed to verify proofs"), culprits...)
		}
	}

	// Fig 5. Output 2. / Fig 6. Output 2.
	xi := new(big.Int).Set(round.temp.shares[i].Share)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		xi = new(big.Int).Add(xi, round.temp.r3msgxij[j])
	}
	round.save.Xi = new(big.Int).Mod(xi, round.EC().Params().N)

	Vc := make([]*crypto.ECPoint, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c]
	}

	{
		var err error
		culprits := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			if j == i {
				continue
			}
			PjVs := round.temp.r2msgVss[j]
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culprits...)
		}
	}

	{
		var err error
		modQ := common.ModInt(round.EC().Params().N)
		culprits := make([]*tss.PartyID, 0)
		for j, Pj := range round.Parties().IDs() {
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := big.NewInt(1)
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if BigXj == nil || err != nil {
					culprits = append(culprits, Pj)
				}
			}
			round.save.BigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
	}

	// Compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(err)
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT party id & public key
	log.Debug(ctx, "%s public key: %x", round.PartyID(), ecdsaPubKey)

	ContextI := append(round.temp.RidAllBz, big.NewInt(int64(i)).Bytes()[:]...)
	// proof, err := zkpsch.NewProof(ctx, ContextI, round.save.BigXj[i], round.save.Xi)
	proof, err := zkpsch.NewProofWithAlpha(ctx, ContextI, round.save.BigXj[i], round.temp.Ai, round.temp.alphai, round.save.Xi, rejectionSample)
	if err != nil {
		return round.WrapError(err)
	}

	r4msg := NewKGRound4Message(round.PartyID(), proof)
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.r4msgpfsch {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			ret = false
			continue
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &roundout5{round}
}
