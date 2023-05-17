from random import randint

adjectives = [
    "Red", "Green", "Blue", "Yellow", "Purple", "Black", "White", "Grey", "Cyan",
    "Magenta", "Orange", "Mauve", "Brown", "Lavender", "Gold", "Silver",
    "Rainbow", "Quick", "Angry", "Sleepy", "Happy", "Weird", "Lumpy", "Frisky",
    "Friendly", "Awkward", "Crazy", "Surly"]

nouns = [
    "Bear", "Hawk", "Beaver", "Pig", "Moose", "Possum", "Skunk", "Elf",
    "Snake", "Lizard", "Eagle", "Dove", "Aardvark", "Wombat", "Dingo",
    "Frog", "Fly", "Bunny", "Ant", "Squid", "Python", "Elephant",
    "Walrus", "Dolphin", "Whale", "Rhino", "Bull", "Cow", "Chicken",
    "Snail", "Mantis", "Vole", "Rat", "Mouse"]

def rand_name()->str:
    i = randint(0, len(adjectives)-1)
    j = randint(0, len(nouns)-1)
    return "%s%s%d" % (adjectives[i], nouns[j], randint(0,100))
