export default _default;
declare function _default(): {
  readonly scrub: () => void;
  readonly exportState: () => ArrayBufferLike;
  readonly importState: (state: AllowSharedBufferSource) => void;
  readonly update: (data: AllowSharedBufferSource) => void;
  readonly finish: () => ArrayBufferLike;
};
