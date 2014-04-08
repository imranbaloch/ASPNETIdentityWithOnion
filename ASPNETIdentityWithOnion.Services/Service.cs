using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.DomainModels;
using ASPNETIdentityWithOnion.Core.Services;


namespace ASPNETIdentityWithOnion.Services
{
    public class Service<TEntity> : IService<TEntity> where TEntity : BaseEntity
    {
        public IUnitOfWork UnitOfWork { get; private set; }
        private readonly IRepository<TEntity> _repository;
        private bool _disposed;

        public Service(IUnitOfWork unitOfWork)
        {
            UnitOfWork = unitOfWork;
            _repository = UnitOfWork.Repository<TEntity>();
        }

        public List<TEntity> GetAll()
        {
            return _repository.GetAll();
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize)
        {
            return _repository.GetAll(pageIndex, pageSize);
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending)
        {
            return _repository.GetAll(pageIndex, pageSize, keySelector, orderBy);
        }

        public PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            return _repository.GetAll(pageIndex, pageSize, keySelector, predicate, orderBy, includeProperties);
        }

        public TEntity GetById(int id)
        {
            return _repository.GetSingle(id);
        }

        public void Add(TEntity entity)
        {
            _repository.Insert(entity);
            UnitOfWork.SaveChanges();
        }
        
        public void Update(TEntity entity)
        {
            _repository.Update(entity);
            UnitOfWork.SaveChanges();
        }

        public void Delete(TEntity entity)
        {
            _repository.Delete(entity);
            UnitOfWork.SaveChanges();
        }

        public Task<List<TEntity>> GetAllAsync()
        {
            return _repository.GetAllAsync();
        }

        public Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize)
        {
            return _repository.GetAllAsync(pageIndex, pageSize);
        }

        public Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending)
        {
            return _repository.GetAllAsync(pageIndex, pageSize, keySelector, orderBy);
        }

        public Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties)
        {
            return _repository.GetAllAsync(pageIndex, pageSize, keySelector, predicate, orderBy, includeProperties);
        }

        public Task<TEntity> GetByIdAsync(int id)
        {
            return _repository.GetSingleAsync(id);
        }

        public Task AddAsync(TEntity entity)
        {
            _repository.Insert(entity);
            return UnitOfWork.SaveChangesAsync();
        }

        public Task UpdateAsync(TEntity entity)
        {
            _repository.Update(entity);
            return UnitOfWork.SaveChangesAsync();
        }

        public Task DeleteAsync(TEntity entity)
        {
            _repository.Delete(entity);
            return UnitOfWork.SaveChangesAsync();
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
                UnitOfWork.Dispose();
            }
            _disposed = true;
        }
    }
}
