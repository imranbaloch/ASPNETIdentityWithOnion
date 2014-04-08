using System;
using System.Collections;
using System.Threading;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.DomainModels;

namespace ASPNETIdentityWithOnion.Data
{
    public class UnitOfWork : IUnitOfWork
    {

        private readonly IEntitiesContext _context;
        private bool _disposed;
        private Hashtable _repositories;

        public UnitOfWork(IEntitiesContext context)
        {
            _context = context;
        }

        public int SaveChanges()
        {
            return _context.SaveChanges();
        }

        public IRepository<TEntity> Repository<TEntity>() where TEntity : BaseEntity
        {
            if (_repositories == null)
            {
                _repositories = new Hashtable();
            }
            var type = typeof(TEntity).Name;
            if (_repositories.ContainsKey(type))
            {
                return (IRepository<TEntity>)_repositories[type];
            }
            var repositoryType = typeof(EntityRepository<>);
            _repositories.Add(type, Activator.CreateInstance(repositoryType.MakeGenericType(typeof(TEntity)), _context));
            return (IRepository<TEntity>)_repositories[type];
        }

        public Task<int> SaveChangesAsync()
        {
            return _context.SaveChangesAsync();
        }

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken)
        {
            return _context.SaveChangesAsync(cancellationToken);
        }

        public void BeginTransaction()
        {
            _context.BeginTransaction();
        }

        public int Commit()
        {
            return _context.Commit();
        }

        public void Rollback()
        {
            _context.Rollback();
        }

        public Task<int> CommitAsync()
        {
            return _context.CommitAsync();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _context.Dispose();
                foreach (IDisposable repository in _repositories.Values)
                {
                    repository.Dispose();// dispose all repositries
                }
            }
            _disposed = true;
        }
    }
}
