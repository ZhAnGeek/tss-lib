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

type EventWatcherKey string

const (
	EventStart EventAction = "start"
	EventEnd   EventAction = "end"

	eventWatcherKey EventWatcherKey = "tss-event-watcher"
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

type EventWatcher struct {
	listener EventListener
}

func NewEventWatcher(listener EventListener) *EventWatcher {
	return &EventWatcher{listener: listener}
}

func (e *EventWatcher) SetEventListener(listener EventListener) {
	e.listener = listener
}

func (e *EventWatcher) GetEventListener() EventListener {
	return e.listener
}

func (e *EventWatcher) EmitEvent(event Event) {
	if e.listener != nil {
		e.listener.OnEvent(event)
	}
}

func (e *EventWatcher) ToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, eventWatcherKey, e)
}

func EventWatcherFromContext(ctx context.Context) (EventObservable, bool) {
	ob, ok := ctx.Value(eventWatcherKey).(*EventWatcher)
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
	ob, ok := EventWatcherFromContext(ctx)
	if !ok {
		return
	}

	ob.EmitEvent(Event{
		Name:   eventName,
		Action: eventAction,
	})
}
