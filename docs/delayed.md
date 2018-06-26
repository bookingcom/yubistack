Token time validity
===================

The algorithm to compute this relies on the OTP low and high values.
We retrieve from the database those previous values, and the unix timestamp 
associated with it.
We then compute the delta between previous values and current one and multiply 
by the clock frequency: 

```text
frequency = 1 / 8
current = high << 16 + low
previous = prev_high << 16 + prev_low
delta = (current - previous) * frequency
unix_delta = epoch - prev_epoch
```

Once we got those values we compute a deviation and the associated percentage,
we then compare to the configuration values.

```text
rel_tolerance = 0.3
abs_tolerance = 20

deviation = abs(unix_delta - delta)
percentage = deviation / unix_delta

delayed = deviation > abs_tolerance && percentage > rel_tolerance
```

__BEWARE__: The time validity can only be computed between tokens issued on the same
plugging time. This mean that we have to check the counter, to be sure that the
one in DB is the same as the one coming.

Clock frequency
---------------

Following the Yubico implementation we see that a Yubikey internal clock has
a frequency of 0.125Hz (1/8). Which means that every time the lower counter increase
by 8, only 1 second elapsed.

Clock reset
-----------

The internal clock of yubikey reset every ~24.25 days. The `high` value is a 8 bit
integer shifted by 16 bit, with an 8Hz frequency.

```text
max_ts = (256 << 16) / 8 = 2097152
days = max_ts / 24 * 3600 = 24.272...
```
