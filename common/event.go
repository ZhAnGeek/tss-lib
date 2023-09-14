// Copyright © 2023 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"fmt"
)

type EventAction string

const (
	EventStart EventAction = "start"
	EventEnd   EventAction = "end"
)

type Event struct {
	Name   string
	Action EventAction
}

type EventListener interface {
	OnEvent(event Event)
}

type EventObservable interface {
	SetEventListener(listener EventListener)
	GetEventListener() EventListener
	EmitEvent(event Event)
}

type EventObserver struct {
	listener EventListener
}

func NewEventObserver(listener EventListener) *EventObserver {
	return &EventObserver{listener: listener}
}

func (e *EventObserver) SetEventListener(listener EventListener) {
	e.listener = listener
}

func (e *EventObserver) GetEventListener() EventListener {
	return e.listener
}

func (e *EventObserver) EmitEvent(event Event) {
	if e.listener != nil {
		e.listener.OnEvent(event)
	}
}

func (e *EventObserver) ToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, eventObserverKey, e)
}

const eventObserverKey = "tss-event-observer"

func EventObserverFromContext(ctx context.Context) (EventObservable, bool) {
	ob, ok := ctx.Value(eventObserverKey).(*EventObserver)
	if !ok {
		return nil, false
	}

	return ob, true
}

func TryEmitTSSRoundStartEvent(ctx context.Context, taskName string, roundName string) {
	TryEmitEvent(ctx, fmt.Sprintf("%s-%s", taskName, roundName), EventStart)
}

func TryEmitTSSRoundEndEvent(ctx context.Context, taskName string, roundName string) {
	TryEmitEvent(ctx, fmt.Sprintf("%s-%s", taskName, roundName), EventEnd)
}

func TryEmitEvent(ctx context.Context, eventName string, eventAction EventAction) {
	ob, ok := EventObserverFromContext(ctx)
	if !ok {
		return
	}

	ob.EmitEvent(Event{
		Name:   eventName,
		Action: eventAction,
	})
}
