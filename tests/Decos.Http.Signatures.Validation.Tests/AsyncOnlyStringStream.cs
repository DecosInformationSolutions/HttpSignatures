using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Decos.Http.Signatures.Tests;

namespace Decos.Http.Signatures.Validation.Tests
{
    internal class AsyncOnlyStringStream : StringStream
    {
        public AsyncOnlyStringStream(string value)
            : base(value)
        {
        }

        public AsyncOnlyStringStream(string value, Encoding encoding)
            : base(value, encoding)
        {
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length
            => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int WriteTimeout
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => throw SyncDisallowed();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) 
            => Task.FromResult(base.Read(buffer, offset, count));

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        private InvalidOperationException SyncDisallowed()
            => new InvalidOperationException("Synchronous operations are disallowed.");
    }
}