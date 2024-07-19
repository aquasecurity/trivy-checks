# METADATA
# custom:
#   library: true

package lib.date

zero_date := "0001-01-01T00:00:00Z"

is_never(date) := date == zero_date

is_valid(date) := date != zero_date
