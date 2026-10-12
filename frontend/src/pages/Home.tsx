import Header from '../components/Header'

function Home() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <Header />
      <main className="mx-auto max-w-5xl px-4 py-6">
        {/* エリアカード・食堂マップ・接続状態はここに配置する */}
      </main>
    </div>
  )
}

export default Home
