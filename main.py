from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise import fields
from tortoise.models import Model
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.contrib.fastapi import register_tortoise
from passlib.hash import bcrypt

app = FastAPI()


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password = fields.CharField(256)

    @classmethod
    async def get_user(cls, username):
        return cls.get(username=username)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password)


User_pydantic = pydantic_model_creator(User, name="User")
UserIn_pydantic = pydantic_model_creator(User, name="UserIn", exclude_readonly=True)



@app.post('/Users', response_model=User_pydantic)
async def create_user(user: UserIn_pydantic):
    user_obj = User(username=user.username, password=bcrypt.hash(user.password))
    await user_obj.save()
    return await User_pydantic.from_tortoise_orm(user_obj)




register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)
