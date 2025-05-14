# Babel routing, but in rust

## I have little clue what I'm doing, please bear with me

### Contributions very welcome

Read the Fricken RFC: https://www.rfc-editor.org/rfc/rfc8966.html

Currently the app will send a hello with an ack-req and some padding when ran

All TLVs are implemented in tlv.rs (I believe) but sub-tlv creation needs to be tested/refined. For recieving sub tlvs and padding in general, I just ignore them for now.