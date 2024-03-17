from typing import List, Union

from fastapi import FastAPI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langserve import add_routes  # type: ignore
from pydantic import BaseModel, Field


app = FastAPI(
    title="Jaffby Server", version="0.0.1", description="FastAPI Jaffby server"
)

# add_routes(app, ChatOpenAI(model="gpt-3.5-turbo"), path="/openai")

# model = ChatOpenAI(model="gpt-3.5-turbo")
# prompt = ChatPromptTemplate.from_template("tell me a joke about {topic}")
# add_routes(app, prompt | model, path="/joke")


# prompt2 = ChatPromptTemplate.from_messages(
#     [
#         ("system", "You are a helpful, professional assistant named Cob."),
#         MessagesPlaceholder(variable_name="messages"),
#     ]
# )

# chain2 = prompt2 | model


# class InputChat(BaseModel):
#     """Input for the chat endpoint."""

#     messages: List[Union[HumanMessage, AIMessage, SystemMessage]] = Field(
#         ...,
#         description="The chat messages representing the current conversation.",
#     )


# add_routes(
#     app,
#     chain2.with_types(input_type=InputChat),
#     enable_feedback_endpoint=True,
#     enable_public_trace_link_endpoint=True,
#     playground_type="chat",
# )


@app.get("/")
async def root():
    return {"message": "Hello World!"}
