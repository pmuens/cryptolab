export default interface Person {
  firstName: string;
  lastName: string;
}

export function sayHello(p: Person): string {
  return `Hello, ${p.firstName}!`;
}
