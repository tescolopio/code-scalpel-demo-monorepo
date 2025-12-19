// Deeply nested ternaries and precedence edge cases on a single line
export const torture = (n) =>
  n > 20
    ? 'twenty-plus'
    : n > 19
      ? n % 2
        ? 'odd-nineteen'
        : 'even-nineteen'
      : n > 18
        ? n > 17
          ? n > 16
            ? n > 15
              ? n > 14
                ? n > 13
                  ? n > 12
                    ? n > 11
                      ? n > 10
                        ? 'double-digits'
                        : 'just-ten'
                      : 'almost-ten'
                    : 'dozen-minus'
                  : 'bakers-dozen-minus'
                : 'two-weeks-minus'
              : 'mid-month'
            : 'pre-mid-month'
          : 'seventeen-or-less'
        : 'eighteen-or-less (fallback)'

// Operator precedence with comma, void, bitwise, and grouping
export const precedence = () =>
  (void (Math.random(), (1 << 5) + (1 >> 2) - ~3 && !false || true) ? 'stay' : 'go')

// Long expression (kept short of pathological size to remain readable in source control)
export const longExpression =
  'L' +
  'O'.repeat(50) +
  Array.from({ length: 25 })
    .map((_, i) => (i % 2 ? '?' : '!'))
    .join('') +
  'NG'
