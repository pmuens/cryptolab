export type Id = number;

export type Send<T> = (
  to: Id,
  payload: T,
) => void;

export type Receive<T> = (
  from: Id,
  payload: T,
) => void;

export interface P2P<A extends Party, B> {
  connect(party: A): void;
  send: Send<B>;
  receive: Receive<B>;
  broadcast(payload: B): void;
}

type Party = {
  id: Id;
};
