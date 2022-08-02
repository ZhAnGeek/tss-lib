// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"errors"
	"fmt"
	"sync"

	"github.com/binance-chain/tss-lib/common"
)

type Party interface {
	Start() *Error
	// The main entry point when updating a party's state from the wire.
	// isBroadcast should represent whether the message was received via a reliable broadcast
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err *Error)
	// You may use this entry point to update a party's state when running locally or in tests
	Update(msg ParsedMessage) (ok bool, err *Error)
	Running() bool
	WaitingFor() []*PartyID
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	FirstRound() Round
	WrapError(err error, culprits ...*PartyID) *Error
	PartyID() *PartyID
	String() string
	AtRoundNumber() int
	ExpectMsgRound() int
	PushMsgToPool(message ParsedMessage) bool
	PopMsgFromPool() (bool, *ParsedMessage)
	TopMsgOfPool() (bool, *ParsedMessage)

	// Private lifecycle methods
	setRound(Round) *Error
	round() Round
	advance()
	lock()
	unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	msgPool    []*ParsedMessage
	poolMtx    sync.Mutex
	FirstRound Round
}

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.lock()
	defer p.unlock()
	if p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	if p.rnd == nil {
		return NewError(err, "", -1, nil, culprits...)
	}
	return p.rnd.WrapError(err, culprits...)
}

// an implementation of ValidateMessage that is shared across the different types of parties (keygen, signing, dynamic groups)
func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) AtRoundNumber() int {
	if p.rnd == nil {
		return 0
	}
	return p.rnd.RoundNumber()
}

func (p *BaseParty) ExpectMsgRound() int {
	return p.AtRoundNumber()
}

func (p *BaseParty) PushMsgToPool(msg ParsedMessage) bool {
	p.poolMtx.Lock()
	defer p.poolMtx.Unlock()
	p.msgPool = append(p.msgPool, &msg)
	maxIdx := len(p.msgPool) - 2
	for i := maxIdx; i >= 0; i-- {
		if (*p.msgPool[i+1]).Content().RoundNumber() >= (*p.msgPool[i]).Content().RoundNumber() {
			break
		}
		p.msgPool[i], p.msgPool[i+1] = p.msgPool[i+1], p.msgPool[i]
	}

	return true
}

func (p *BaseParty) PopMsgFromPool() (ok bool, pMsg *ParsedMessage) {
	p.poolMtx.Lock()
	defer p.poolMtx.Unlock()
	if len(p.msgPool) == 0 {
		return false, nil
	}
	hMsg := p.msgPool[0]
	p.msgPool = p.msgPool[1:]
	return true, hMsg
}

func (p *BaseParty) TopMsgOfPool() (ok bool, pMsg *ParsedMessage) {
	p.poolMtx.Lock()
	defer p.poolMtx.Unlock()
	if len(p.msgPool) == 0 {
		return false, nil
	}
	hMsg := p.msgPool[0]
	return true, hMsg
}

func (p *BaseParty) String() string {
	if p.round() == nil {
		return "round: <nil>"
	}
	return fmt.Sprintf("round: %d", p.round().RoundNumber())
}

// -----
// Private lifecycle methods

func (p *BaseParty) setRound(round Round) *Error {
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) lock() {
	p.mtx.Lock()
}

func (p *BaseParty) unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string, prepare ...func(Round) *Error) *Error {
	p.lock()
	defer p.unlock()
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.round() != nil {
		p.round().SetStarted(false)
		return p.round().Start() // start from restored round
		// return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}
	if 1 < len(prepare) {
		return p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}
	common.Logger.Infof("party %v: %s round %d starting", p.round().Params().PartyID(), task, 1)
	defer func() {
		common.Logger.Debugf("party %v: %s round %d finished", p.round().Params().PartyID(), task, 1)
	}()
	return p.round().Start()
}

func BaseRestore(p Party, task string) *Error {
	p.lock()
	defer p.unlock()
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not restore %s. this party has an invalid PartyID: %+v", task, p.PartyID()))
	}
	if p.round() != nil {
		return p.WrapError(errors.New("could not restore. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	err := p.setRound(round)
	if err != nil {
		return err
	}
	p.round().SetStarted(true)
	return nil
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.unlock()
		return ok, err
	}
	p.lock() // data is written to P state below
	common.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		common.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		common.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return r(false, err)
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish
		}
		return r(true, nil)
	}
	return r(true, nil)
}

// Non-recursive version of BaseUpdate, in order to use it, it should make sure that party is updated by messages in correct round order
func BaseUpdateNR(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	p.lock() // data is written to P state below
	defer p.unlock()
	common.Logger.Debugf("party %v received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		common.Logger.Debugf("party %v round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return false, err
	}
	if p.round() != nil {
		common.Logger.Debugf("party %v: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return false, err
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					rndNum := p.round().RoundNumber()
					common.Logger.Debugf("party %v: %s round %d started with Err", p.round().Params().PartyID(), task, rndNum)
					return false, err
				}
				rndNum := p.round().RoundNumber()
				common.Logger.Infof("party %v: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				common.Logger.Infof("party %v: %s finished!", p.PartyID(), task)
			}
		}
	}
	return true, nil
}

func BaseUpdatePool(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	r := func(ok bool, err *Error) (bool, *Error) {
		p.unlock()
		return ok, err
	}
	p.lock()
	if msg.Content().RoundNumber() > p.ExpectMsgRound() {
		common.Logger.Debugf("party %v: %s will pool msg %d", p.round().Params().PartyID(), task, p.ExpectMsgRound())
		p.PushMsgToPool(msg)
		return r(true, nil)
	}
	if msg.Content().RoundNumber() < p.ExpectMsgRound() {
		// drop message
		common.Logger.Debugf("party %v: %s will drop msg %d", p.round().Params().PartyID(), task, msg.Content().RoundNumber())
		return r(true, nil)
	}

	p.unlock()
	ok, err = BaseUpdateNR(p, msg, task)
	if !ok {
		return r(ok, err)
	}
	p.lock()
	for {
		ok, hMsg := p.TopMsgOfPool()
		if !ok {
			common.Logger.Debugf("party %v: %s accessing empty pool", p.PartyID(), task)
			break
		}
		hRnd := (*hMsg).Content().RoundNumber()
		if hRnd > p.ExpectMsgRound() {
			common.Logger.Debugf("party %v: %s message pool not updateable %d", p.PartyID(), task, hRnd)
			break
		}
		ok, hMsg = p.PopMsgFromPool()
		if !ok {
			break
		}
		if hRnd == p.ExpectMsgRound() {
			p.unlock()
			ok, err = BaseUpdateNR(p, *hMsg, task)
			if !ok {
				return ok, err
			}
			p.lock()
		}
	}

	return r(true, nil)
}
