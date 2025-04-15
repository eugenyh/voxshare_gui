import opuslib

class AudioCodec:
    def __init__(self):
        self.encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, 'voip')
        self.decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
        self.encoder.bitrate = 16000  # 16 кбит/с
        
    def encode(self, pcm_data):
        return self.encoder.encode(pcm_data, BLOCKSIZE)
    
    def decode(self, encoded_data):
        return self.decoder.decode(encoded_data, BLOCKSIZE)
