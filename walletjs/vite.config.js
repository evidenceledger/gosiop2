import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig(({ command, mode }) => {
    // command can be 'dev', 'serve' or 'build'
    // We can use conditionals to return different configs if needed
    return {
        // config options
        root: "src",
        base: "./",
        json: {
            stringify: true
        },
        build: {
            minify: "esbuild",
            outDir: "../www",
            emptyOutDir: true,
            assetsInlineLimit: 20000,
            chunkSizeWarningLimit: 2000,
            manifest: true,
            sourcemap: true,
            rollupOptions: {
                input: {
                  main: resolve(__dirname, 'src', 'index.html'),
                  wallet: resolve(__dirname, 'src', 'wallet.html')
                },
              }

        }

    }
})
