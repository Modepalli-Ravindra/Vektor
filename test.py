import numpy as np
from PIL import Image

# Simulate a malware-like PE visualization
# Dense, high-entropy byte patterns typical of packed malware
np.random.seed(42)
data = np.random.randint(0, 256, (32, 32), dtype=np.uint8)
Image.fromarray(data).save("test_malware.png")