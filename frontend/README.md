# 食堂混雑状況 フロントエンド

Vite + React + TypeScript + Tailwind CSS。

## 起動

```sh
cd frontend
npm install
npm run dev
```

ブラウザで http://localhost:5173 を開くと「食堂混雑状況」のタイトルが表示されます。
同じネットワークのスマホからは、ターミナルに表示される `Network:` の URL で確認できます。

## コマンド

| コマンド | 内容 |
| --- | --- |
| `npm run dev` | 開発サーバー起動 |
| `npm run build` | 型チェックと本番ビルド(`dist/`) |
| `npm run lint` | oxlint による静的解析 |
| `npm run preview` | ビルド結果の確認 |

## ディレクトリ構成

```
src/
├── App.tsx            # ルート
├── pages/Home.tsx     # メイン画面
├── components/        # 画面部品(Header ほか)
├── api/               # WebSocket 通信(予定)
└── hooks/             # useOccupancy など(予定)
```
