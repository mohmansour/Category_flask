from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Sport, Base, Item, User , Latest

engine = create_engine('sqlite:///sport.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

#create categories 

#hi
sport1 = Sport(user_id=1, name="Soccer")

session.add(sport1)
session.commit()

item1 = Item(user_id=1, name="Ball", description="each 11 players work on shooting it into the opposite team ", sport=sport1)

item1 = Latest(user_id=1, name="Ball", description="each 11 players work on shooting it into the opposite team ", sport=sport1)

session.add(item1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Basketball")

session.add(sport1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Baseball")

session.add(sport1)
session.commit()

item1 = Item(user_id=1, name="Bat", description="to hit ball ", sport=sport1)

item1 = Latest(user_id=1, name="Bat", description="to hit ball ", sport=sport1)

session.add(item1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Frisbee")

session.add(sport1)
session.commit()

item1 = Item(user_id=1, name="frisbee", description="thrown plate ", sport=sport1)

item1 = Latest(user_id=1, name="frisbee", description="thrown plate ", sport=sport1)

session.add(item1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Rock Climbing")

session.add(sport1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Foosball ")

session.add(sport1)
session.commit()

#hi
sport1 = Sport(user_id=1, name="Snowboarding ")

session.add(sport1)
session.commit()

item1 = Item(user_id=1, name="Goggles", description="each 11 players work on shooting it into the opposite team ", sport=sport1)

item1 = Latest(user_id=1, name="Snowboard", description="Best for any terrain & conditions", sport=sport1)

session.add(item1)
session.commit()


#hi
sport1 = Sport(user_id=1, name="Skating ")

session.add(sport1)
session.commit()

#hi
sport1 = Sport(user_id=1, name="Hockey")

session.add(sport1)
session.commit()

item1 = Item(user_id=1, name="Stick", description="used to move the black block", sport=sport1)

item1 = Latest(user_id=1, name="Stick", description="used to move the black block", sport=sport1)

session.add(item1)
session.commit()


print "added sports!"
