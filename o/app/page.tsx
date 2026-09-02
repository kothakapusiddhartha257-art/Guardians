import { Hero } from '@/components/home/hero'
import { Story } from '@/components/home/story'
import { ThreeAxis } from '@/components/home/three-axis'
import { Lenses } from '@/components/home/lenses'
import { Closing } from '@/components/home/closing'

export default function HomePage() {
  return (
    <>
      <Hero />
      <Story />
      <ThreeAxis />
      <Lenses />
      <Closing />
    </>
  )
}
