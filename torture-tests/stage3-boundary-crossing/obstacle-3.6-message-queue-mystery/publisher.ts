// Obstacle 3.6 publisher: tainted user input is published to Kafka without any validation.
import { Kafka } from 'kafkajs'

const kafka = new Kafka({ clientId: 'web', brokers: ['kafka:9092'] })
const producer = kafka.producer()

export async function publishComment(userId: string, rawComment: string) {
  await producer.connect()
  await producer.send({
    topic: 'comments',
    messages: [
      {
        key: userId,
        value: JSON.stringify({
          userId,
          comment: rawComment, // untrusted data crossing async boundary
          at: Date.now()
        })
      }
    ]
  })
  await producer.disconnect()
}
