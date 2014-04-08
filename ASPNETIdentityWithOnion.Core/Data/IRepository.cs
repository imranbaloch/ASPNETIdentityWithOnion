using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.DomainModels;

namespace ASPNETIdentityWithOnion.Core.Data
{
    public interface IRepository<TEntity> : IDisposable where TEntity : BaseEntity
    {
        List<TEntity> GetAll();
        PaginatedList<TEntity> GetAll(int pageIndex, int pageSize);
        PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending);
        PaginatedList<TEntity> GetAll(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties);
        List<TEntity> GetAllIncluding(params Expression<Func<TEntity, object>>[] includeProperties);
        TEntity GetSingle(int id);
        TEntity GetSingleIncluding(int id, params Expression<Func<TEntity, object>>[] includeProperties);
        List<TEntity> FindBy(Expression<Func<TEntity, bool>> predicate);
        void Insert(TEntity entity);
        void Update(TEntity entity);
        void Delete(TEntity entity);
        Task<List<TEntity>> GetAllAsync();
        Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize);
        Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, OrderBy orderBy = OrderBy.Ascending);
        Task<PaginatedList<TEntity>> GetAllAsync(int pageIndex, int pageSize, Expression<Func<TEntity, int>> keySelector, Expression<Func<TEntity, bool>> predicate, OrderBy orderBy, params Expression<Func<TEntity, object>>[] includeProperties);
        Task<List<TEntity>> GetAllIncludingAsync(params Expression<Func<TEntity, object>>[] includeProperties);
        Task<TEntity> GetSingleAsync(int id);
        Task<TEntity> GetSingleIncludingAsync(int id, params Expression<Func<TEntity, object>>[] includeProperties);
        Task<List<TEntity>> FindByAsync(Expression<Func<TEntity, bool>> predicate);
    }
}
