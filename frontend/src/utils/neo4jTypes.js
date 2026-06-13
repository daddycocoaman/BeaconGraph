export function isNode(value) {
  return Boolean(
    value &&
      Array.isArray(value.labels) &&
      value.properties &&
      Object.prototype.hasOwnProperty.call(value, "identity")
  );
}

export function isRelationship(value) {
  return Boolean(
    value &&
      value.properties &&
      typeof value.type === "string" &&
      Object.prototype.hasOwnProperty.call(value, "start") &&
      Object.prototype.hasOwnProperty.call(value, "end") &&
      Object.prototype.hasOwnProperty.call(value, "identity")
  );
}