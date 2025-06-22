function weightedFuzzSelectors(selectors) {
  const weighted = [];

  selectors.forEach(s => {
    const weight = (s.entropy + 1) * (s.drift + 1);
    for (let i = 0; i < weight; i++) weighted.push(s.selector);
  });

  return shuffle(weighted);
}
