import time # add this to the top of your file

before = time.perf_counter() # put this before code you want to time

after = time.perf_counter()
print(f"{after - before:0.4f} seconds") # put these 2 lines after code you want to time